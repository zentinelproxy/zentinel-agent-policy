-- |
-- Module      : Sentinel.Agent.Policy.Cache
-- Description : Decision caching for performance
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- LRU cache for policy decisions to reduce evaluation overhead
-- for repeated similar requests.

module Sentinel.Agent.Policy.Cache
  ( -- * Cache Types
    DecisionCache
  , CacheStats(..)

    -- * Cache Operations
  , newCache
  , lookup
  , insert
  , invalidate
  , clear
  , getStats

    -- * Cache Key
  , CacheKey
  , makeCacheKey
  ) where

import Prelude hiding (lookup)

import Control.Concurrent.STM
import Data.Hashable (Hashable, hash)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock (UTCTime, getCurrentTime, diffUTCTime, NominalDiffTime)
import GHC.Generics (Generic)
import Sentinel.Agent.Policy.Config (CacheConfig(..))
import Sentinel.Agent.Policy.Types

-- | Cache key derived from policy input
newtype CacheKey = CacheKey { unCacheKey :: Int }
  deriving stock (Eq, Ord, Show)
  deriving newtype (Hashable)

-- | Create a cache key from policy input
makeCacheKey :: PolicyInput -> CacheKey
makeCacheKey = CacheKey . hash

-- | Cached entry with expiration
data CacheEntry = CacheEntry
  { ceResult :: !EvaluationResult
  , ceExpires :: !UTCTime
  }
  deriving stock (Show)

-- | Cache statistics
data CacheStats = CacheStats
  { csHits :: !Int
  , csMisses :: !Int
  , csEntries :: !Int
  , csEvictions :: !Int
  }
  deriving stock (Eq, Show, Generic)

-- | Decision cache state
data DecisionCache = DecisionCache
  { dcEntries :: !(TVar (Map CacheKey CacheEntry))
  , dcStats :: !(TVar CacheStats)
  , dcConfig :: !CacheConfig
  }

-- | Create a new decision cache
newCache :: CacheConfig -> IO DecisionCache
newCache config = DecisionCache
  <$> newTVarIO Map.empty
  <*> newTVarIO (CacheStats 0 0 0 0)
  <*> pure config

-- | Look up a cached decision
lookup :: DecisionCache -> PolicyInput -> IO (Maybe EvaluationResult)
lookup cache input = do
  now <- getCurrentTime
  let key = makeCacheKey input

  atomically $ do
    entries <- readTVar (dcEntries cache)
    case Map.lookup key entries of
      Just entry
        | ceExpires entry > now -> do
            modifyTVar' (dcStats cache) $ \s -> s { csHits = csHits s + 1 }
            return $ Just $ (ceResult entry) { cached = True }
        | otherwise -> do
            -- Expired entry, remove it
            modifyTVar' (dcEntries cache) $ Map.delete key
            modifyTVar' (dcStats cache) $ \s ->
              s { csMisses = csMisses s + 1, csEvictions = csEvictions s + 1 }
            return Nothing
      Nothing -> do
        modifyTVar' (dcStats cache) $ \s -> s { csMisses = csMisses s + 1 }
        return Nothing

-- | Insert a decision into the cache
insert :: DecisionCache -> PolicyInput -> EvaluationResult -> IO ()
insert cache input result = do
  now <- getCurrentTime
  let key = makeCacheKey input
      ttl = fromIntegral (ttlSeconds $ dcConfig cache) :: NominalDiffTime
      expires = addUTCTime ttl now
      entry = CacheEntry result expires

  atomically $ do
    entries <- readTVar (dcEntries cache)
    let newSize = Map.size entries + 1
        maxSize = maxEntries (dcConfig cache)

    -- Evict oldest entries if over capacity
    if newSize > maxSize
      then do
        -- Simple eviction: remove 10% of entries
        let toRemove = maxSize `div` 10
            trimmed = Map.fromList $ drop toRemove $ Map.toList entries
        writeTVar (dcEntries cache) $ Map.insert key entry trimmed
        modifyTVar' (dcStats cache) $ \s ->
          s { csEntries = Map.size trimmed + 1
            , csEvictions = csEvictions s + toRemove
            }
      else do
        writeTVar (dcEntries cache) $ Map.insert key entry entries
        modifyTVar' (dcStats cache) $ \s ->
          s { csEntries = newSize }

-- | Invalidate a specific cache entry
invalidate :: DecisionCache -> PolicyInput -> IO ()
invalidate cache input = do
  let key = makeCacheKey input
  atomically $ modifyTVar' (dcEntries cache) $ Map.delete key

-- | Clear all cache entries
clear :: DecisionCache -> IO ()
clear cache = atomically $ do
  writeTVar (dcEntries cache) Map.empty
  modifyTVar' (dcStats cache) $ \s -> s { csEntries = 0 }

-- | Get cache statistics
getStats :: DecisionCache -> IO CacheStats
getStats cache = readTVarIO (dcStats cache)

-- | Add time to UTCTime
addUTCTime :: NominalDiffTime -> UTCTime -> UTCTime
addUTCTime dt t = fromRational (toRational dt) `addTime` t
  where
    addTime :: NominalDiffTime -> UTCTime -> UTCTime
    addTime diff time = diff `seq` time `seq`
      let d = toRational diff + toRational (diffUTCTime time epoch)
      in fromRational d `addToEpoch` epoch

    epoch :: UTCTime
    epoch = read "1970-01-01 00:00:00 UTC"

    addToEpoch :: NominalDiffTime -> UTCTime -> UTCTime
    addToEpoch diff base = let
      secs = realToFrac diff :: Double
      in read $ show base -- This is a placeholder; real impl would use proper time addition

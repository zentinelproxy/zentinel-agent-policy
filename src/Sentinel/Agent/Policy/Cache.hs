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
import Data.Time.Clock (UTCTime, getCurrentTime, diffUTCTime, addUTCTime, NominalDiffTime)
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
  , ceInsertedAt :: !UTCTime
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
              s { csMisses = csMisses s + 1
                , csEvictions = csEvictions s + 1
                , csEntries = csEntries s - 1
                }
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
      entry = CacheEntry
        { ceResult = result
        , ceExpires = expires
        , ceInsertedAt = now
        }

  atomically $ do
    entries <- readTVar (dcEntries cache)
    let currentSize = Map.size entries
        maxSize = maxEntries (dcConfig cache)
        alreadyExists = Map.member key entries

    -- Evict oldest entries if over capacity and adding new entry
    if currentSize >= maxSize && not alreadyExists
      then do
        -- Remove 10% of oldest entries
        let toRemove = max 1 (maxSize `div` 10)
            sortedByAge = Map.toList entries
            -- Keep newer entries (drop oldest)
            trimmed = Map.fromList $ drop toRemove sortedByAge
        writeTVar (dcEntries cache) $ Map.insert key entry trimmed
        modifyTVar' (dcStats cache) $ \s ->
          s { csEntries = Map.size trimmed + 1
            , csEvictions = csEvictions s + toRemove
            }
      else do
        writeTVar (dcEntries cache) $ Map.insert key entry entries
        modifyTVar' (dcStats cache) $ \s ->
          if alreadyExists
            then s  -- No change in entry count for updates
            else s { csEntries = csEntries s + 1 }

-- | Invalidate a specific cache entry
invalidate :: DecisionCache -> PolicyInput -> IO ()
invalidate cache input = do
  let key = makeCacheKey input
  atomically $ do
    entries <- readTVar (dcEntries cache)
    when (Map.member key entries) $ do
      modifyTVar' (dcEntries cache) $ Map.delete key
      modifyTVar' (dcStats cache) $ \s -> s { csEntries = csEntries s - 1 }
  where
    when cond action = if cond then action else return ()

-- | Clear all cache entries
clear :: DecisionCache -> IO ()
clear cache = atomically $ do
  writeTVar (dcEntries cache) Map.empty
  modifyTVar' (dcStats cache) $ \s -> s { csEntries = 0 }

-- | Get cache statistics
getStats :: DecisionCache -> IO CacheStats
getStats cache = readTVarIO (dcStats cache)

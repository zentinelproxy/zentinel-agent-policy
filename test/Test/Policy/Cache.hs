{-# LANGUAGE OverloadedStrings #-}

module Test.Policy.Cache (spec) where

import Test.Hspec
import Test.QuickCheck

import qualified Data.Map.Strict as Map
import Sentinel.Agent.Policy
import Sentinel.Agent.Policy.Cache as Cache

spec :: Spec
spec = do
  describe "DecisionCache" $ do
    it "creates an empty cache" $ do
      cache <- Cache.newCache defaultCacheConfig
      stats <- Cache.getStats cache
      csEntries stats `shouldBe` 0
      csHits stats `shouldBe` 0
      csMisses stats `shouldBe` 0

    it "returns Nothing for cache miss" $ do
      cache <- Cache.newCache defaultCacheConfig
      let input = testInput
      result <- Cache.lookup cache input
      result `shouldBe` Nothing

      stats <- Cache.getStats cache
      csMisses stats `shouldBe` 1

    it "returns cached result for cache hit" $ pending

    it "respects TTL expiration" $ pending

    it "evicts entries when over capacity" $ pending

    it "clears all entries" $ do
      cache <- Cache.newCache defaultCacheConfig
      Cache.clear cache
      stats <- Cache.getStats cache
      csEntries stats `shouldBe` 0

-- Test fixtures
testInput :: PolicyInput
testInput = PolicyInput
  { principal = Principal
      { principalId = "user-123"
      , principalType = Just "User"
      , attributes = Map.empty
      }
  , action = Action
      { actionName = "read"
      , method = "GET"
      }
  , resource = Resource
      { resourceId = "doc-456"
      , resourceType = Just "Document"
      , path = "/api/documents/456"
      , attributes = Map.empty
      }
  , context = Map.empty
  }

defaultCacheConfig :: CacheConfig
defaultCacheConfig = CacheConfig
  { enabled = True
  , ttlSeconds = 60
  , maxEntries = 1000
  }

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}

module Test.Policy.Cache (spec) where

import Test.Hspec
import Test.QuickCheck

import Control.Concurrent (threadDelay)
import Data.Map.Strict qualified as Map
import Data.Text qualified as T

import Zentinel.Agent.Policy
import Zentinel.Agent.Policy.Cache qualified as Cache
import Zentinel.Agent.Policy.Types (Principal(..), Resource(..), Action(..))

spec :: Spec
spec = do
  describe "DecisionCache" $ do
    it "creates an empty cache" $ do
      cache <- newCache defaultCacheConfig
      stats <- Cache.getStats cache
      csEntries stats `shouldBe` 0
      csHits stats `shouldBe` 0
      csMisses stats `shouldBe` 0

    it "returns Nothing for cache miss" $ do
      cache <- newCache defaultCacheConfig
      let input = testInput
      result <- Cache.lookup cache input
      result `shouldBe` Nothing

      stats <- Cache.getStats cache
      csMisses stats `shouldBe` 1

    it "returns cached result for cache hit" $ do
      cache <- newCache defaultCacheConfig
      let input = testInput
          evalResult = EvaluationResult
            { decision = Allow
            , reason = DecisionReason
                { matchedPolicies = ["test-policy"]
                , message = Just "Test"
                , details = Nothing
                }
            , evaluationTimeNs = 1000
            , cached = False
            }

      -- Insert into cache
      Cache.insert cache input evalResult

      -- Lookup should hit
      result <- Cache.lookup cache input
      case result of
        Just r -> do
          decision r `shouldBe` Allow
          Zentinel.Agent.Policy.cached r `shouldBe` True
        Nothing -> expectationFailure "Expected cache hit"

      stats <- Cache.getStats cache
      csHits stats `shouldBe` 1

    it "respects TTL expiration" $ do
      -- Use very short TTL for testing
      let config = CacheConfig
            { enabled = True
            , ttlSeconds = 1
            , maxEntries = 100
            }
      cache <- newCache config

      let input = testInput
          evalResult = EvaluationResult
            { decision = Allow
            , reason = DecisionReason
                { matchedPolicies = ["test-policy"]
                , message = Just "Test"
                , details = Nothing
                }
            , evaluationTimeNs = 1000
            , cached = False
            }

      -- Insert into cache
      Cache.insert cache input evalResult

      -- Should hit immediately
      result1 <- Cache.lookup cache input
      result1 `shouldSatisfy` \case
        Just _ -> True
        Nothing -> False

      -- Wait for TTL to expire
      threadDelay 1500000  -- 1.5 seconds

      -- Should miss after TTL
      result2 <- Cache.lookup cache input
      result2 `shouldBe` Nothing

    it "evicts entries when over capacity" $ do
      let config = CacheConfig
            { enabled = True
            , ttlSeconds = 60
            , maxEntries = 5  -- Very small cache
            }
      cache <- newCache config

      let evalResult = EvaluationResult
            { decision = Allow
            , reason = DecisionReason
                { matchedPolicies = ["test"]
                , message = Nothing
                , details = Nothing
                }
            , evaluationTimeNs = 100
            , cached = False
            }

      -- Insert more entries than capacity
      mapM_ (\i -> Cache.insert cache (testInputWithId i) evalResult) [1..10]

      stats <- Cache.getStats cache
      -- Should have evicted some entries
      csEntries stats `shouldSatisfy` (<= 10)
      csEvictions stats `shouldSatisfy` (> 0)

    it "clears all entries" $ do
      cache <- newCache defaultCacheConfig

      let evalResult = EvaluationResult
            { decision = Allow
            , reason = DecisionReason
                { matchedPolicies = ["test"]
                , message = Nothing
                , details = Nothing
                }
            , evaluationTimeNs = 100
            , cached = False
            }

      -- Insert some entries
      mapM_ (\i -> Cache.insert cache (testInputWithId i) evalResult) [1..5]

      stats1 <- Cache.getStats cache
      csEntries stats1 `shouldSatisfy` (> 0)

      -- Clear cache
      Cache.clear cache

      stats2 <- Cache.getStats cache
      csEntries stats2 `shouldBe` 0

    it "invalidates specific entry" $ do
      cache <- newCache defaultCacheConfig

      let evalResult = EvaluationResult
            { decision = Allow
            , reason = DecisionReason
                { matchedPolicies = ["test"]
                , message = Nothing
                , details = Nothing
                }
            , evaluationTimeNs = 100
            , cached = False
            }

      let input1 = testInputWithId 1
          input2 = testInputWithId 2

      Cache.insert cache input1 evalResult
      Cache.insert cache input2 evalResult

      -- Both should hit
      result1 <- Cache.lookup cache input1
      result1 `shouldSatisfy` \case Just _ -> True; Nothing -> False

      result2 <- Cache.lookup cache input2
      result2 `shouldSatisfy` \case Just _ -> True; Nothing -> False

      -- Invalidate input1
      Cache.invalidate cache input1

      -- input1 should miss, input2 should hit
      result1' <- Cache.lookup cache input1
      result1' `shouldBe` Nothing

      result2' <- Cache.lookup cache input2
      result2' `shouldSatisfy` \case Just _ -> True; Nothing -> False

-- Test fixtures
defaultCacheConfig :: CacheConfig
defaultCacheConfig = CacheConfig
  { enabled = True
  , ttlSeconds = 60
  , maxEntries = 1000
  }

testInput :: PolicyInput
testInput = testInputWithId 0

testInputWithId :: Int -> PolicyInput
testInputWithId i = PolicyInput
  { principal = Principal
      { principalId = "user-" <> T.pack (show i)
      , principalType = Just "User"
      , attributes = Map.empty
      }
  , action = Action
      { actionName = "read"
      , method = "GET"
      }
  , resource = Resource
      { resourceId = "doc-" <> T.pack (show i)
      , resourceType = Just "Document"
      , path = "/api/documents/" <> T.pack (show i)
      , attributes = Map.empty
      }
  , context = Map.empty
  }

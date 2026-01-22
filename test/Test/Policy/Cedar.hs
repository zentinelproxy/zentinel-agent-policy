{-# LANGUAGE OverloadedStrings #-}

module Test.Policy.Cedar (spec) where

import Test.Hspec
import Test.QuickCheck

import Control.Exception (try, SomeException)
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import System.Directory (findExecutable)
import System.IO.Temp (withSystemTempDirectory)
import Data.Text.IO qualified as TIO

import Sentinel.Agent.Policy
import Sentinel.Agent.Policy.Types (Policy(..), Principal(..), Resource(..), Action(..))

spec :: Spec
spec = do
  describe "CedarEngine" $ do
    it "creates a new engine" $ do
      engine <- newCedarEngine
      policies <- getPolicyInfo engine
      policies `shouldBe` []

    it "adds policies" $ do
      engine <- newCedarEngine
      let policy = Policy
            { policyId = "test-policy"
            , Sentinel.Agent.Policy.Types.engine = CedarEngine
            , content = "permit(principal, action, resource);"
            , source = InlineSource "permit(principal, action, resource);"
            }
      result <- addPolicy engine policy
      result `shouldBe` Right ()

      policies <- getPolicyInfo engine
      length policies `shouldBe` 1

    it "clears policies" $ do
      engine <- newCedarEngine
      let policy = Policy
            { policyId = "test-policy"
            , Sentinel.Agent.Policy.Types.engine = CedarEngine
            , content = "permit(principal, action, resource);"
            , source = InlineSource "permit(principal, action, resource);"
            }
      _ <- addPolicy engine policy
      clearPolicies engine
      policies <- getPolicyInfo engine
      policies `shouldBe` []

  describe "evaluate" $ do
    it "returns error when no policies loaded" $ do
      engine <- newCedarEngine
      let input = testInput
      result <- evaluate engine input
      case result of
        Left (EvaluationError msg) ->
          msg `shouldBe` "No Cedar policies loaded"
        _ -> expectationFailure "Expected EvaluationError"

    -- These tests require cedar CLI
    describe "with cedar CLI" $ beforeAll checkCedarCLI $ do
      it "evaluates a simple permit policy" $ \hasCedar -> do
        if not hasCedar
          then pendingWith "cedar CLI not installed"
          else do
            engine <- newCedarEngine
            let policy = Policy
                  { policyId = "allow-all"
                  , Sentinel.Agent.Policy.Types.engine = CedarEngine
                  , content = "permit(principal, action, resource);"
                  , source = InlineSource "permit(principal, action, resource);"
                  }
            _ <- addPolicy engine policy
            result <- evaluate engine testInput
            case result of
              Right evalResult -> decision evalResult `shouldBe` Allow
              Left err -> expectationFailure $ "Evaluation failed: " ++ show err

      it "evaluates a forbid policy" $ \hasCedar -> do
        if not hasCedar
          then pendingWith "cedar CLI not installed"
          else do
            engine <- newCedarEngine
            let policy = Policy
                  { policyId = "deny-all"
                  , Sentinel.Agent.Policy.Types.engine = CedarEngine
                  , content = "forbid(principal, action, resource);"
                  , source = InlineSource "forbid(principal, action, resource);"
                  }
            _ <- addPolicy engine policy
            result <- evaluate engine testInput
            case result of
              Right evalResult -> decision evalResult `shouldBe` Deny
              Left err -> expectationFailure $ "Evaluation failed: " ++ show err

-- Check if cedar CLI is available
checkCedarCLI :: IO Bool
checkCedarCLI = do
  result <- findExecutable "cedar"
  return $ case result of
    Just _ -> True
    Nothing -> False

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

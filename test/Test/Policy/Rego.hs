{-# LANGUAGE OverloadedStrings #-}

module Test.Policy.Rego (spec) where

import Test.Hspec
import Test.QuickCheck

import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import System.Directory (findExecutable)

import Zentinel.Agent.Policy
import Zentinel.Agent.Policy.Types (Policy(..), Principal(..), Resource(..), Action(..))

spec :: Spec
spec = do
  describe "RegoEngine" $ do
    it "creates a new engine" $ do
      engine <- newRegoEngine
      policies <- getPolicyInfo engine
      policies `shouldBe` []

    it "extracts package name from policy" $ do
      engine <- newRegoEngine
      let policy = Policy
            { policyId = "test-policy"
            , Zentinel.Agent.Policy.Types.engine = RegoEngine
            , content = "package zentinel.authz\n\ndefault allow := false"
            , source = InlineSource "package zentinel.authz\n\ndefault allow := false"
            }
      result <- addPolicy engine policy
      result `shouldBe` Right ()

      policies <- getPolicyInfo engine
      case policies of
        [(_, pkg)] -> pkg `shouldBe` "zentinel.authz"
        _ -> expectationFailure "Expected one policy"

    it "clears policies" $ do
      engine <- newRegoEngine
      let policy = Policy
            { policyId = "test-policy"
            , Zentinel.Agent.Policy.Types.engine = RegoEngine
            , content = "package test\n\ndefault allow := false"
            , source = InlineSource "package test\n\ndefault allow := false"
            }
      _ <- addPolicy engine policy
      clearPolicies engine
      policies <- getPolicyInfo engine
      policies `shouldBe` []

  describe "evaluate" $ do
    it "returns error when no policies loaded" $ do
      engine <- newRegoEngine
      let input = testInput
      result <- evaluate engine input
      case result of
        Left (EvaluationError msg) ->
          msg `shouldBe` "No Rego policies loaded"
        _ -> expectationFailure "Expected EvaluationError"

    -- These tests require opa CLI
    describe "with opa CLI" $ beforeAll checkOpaCLI $ do
      it "evaluates a simple allow policy" $ \hasOpa -> do
        if not hasOpa
          then pendingWith "opa CLI not installed"
          else do
            engine <- newRegoEngine
            let policy = Policy
                  { policyId = "allow-all"
                  , Zentinel.Agent.Policy.Types.engine = RegoEngine
                  , content = T.unlines
                      [ "package zentinel.authz"
                      , ""
                      , "default allow := true"
                      ]
                  , source = InlineSource ""
                  }
            _ <- addPolicy engine policy
            result <- evaluate engine testInput
            case result of
              Right evalResult -> decision evalResult `shouldBe` Allow
              Left err -> expectationFailure $ "Evaluation failed: " ++ show err

      it "evaluates a deny policy" $ \hasOpa -> do
        if not hasOpa
          then pendingWith "opa CLI not installed"
          else do
            engine <- newRegoEngine
            let policy = Policy
                  { policyId = "deny-all"
                  , Zentinel.Agent.Policy.Types.engine = RegoEngine
                  , content = T.unlines
                      [ "package zentinel.authz"
                      , ""
                      , "default allow := false"
                      ]
                  , source = InlineSource ""
                  }
            _ <- addPolicy engine policy
            result <- evaluate engine testInput
            case result of
              Right evalResult -> decision evalResult `shouldBe` Deny
              Left err -> expectationFailure $ "Evaluation failed: " ++ show err

      it "evaluates conditional policy" $ \hasOpa -> do
        if not hasOpa
          then pendingWith "opa CLI not installed"
          else do
            engine <- newRegoEngine
            let policy = Policy
                  { policyId = "conditional"
                  , Zentinel.Agent.Policy.Types.engine = RegoEngine
                  , content = T.unlines
                      [ "package zentinel.authz"
                      , ""
                      , "default allow := false"
                      , ""
                      , "allow {"
                      , "  input.action == \"read\""
                      , "}"
                      ]
                  , source = InlineSource ""
                  }
            _ <- addPolicy engine policy
            -- Should allow read action
            result <- evaluate engine testInput
            case result of
              Right evalResult -> decision evalResult `shouldBe` Allow
              Left err -> expectationFailure $ "Evaluation failed: " ++ show err

-- Check if opa CLI is available
checkOpaCLI :: IO Bool
checkOpaCLI = do
  result <- findExecutable "opa"
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

{-# LANGUAGE OverloadedStrings #-}

module Test.Policy.Rego (spec) where

import Test.Hspec
import Test.QuickCheck

import qualified Data.Map.Strict as Map
import Sentinel.Agent.Policy

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
            , engine = RegoEngine
            , content = "package sentinel.authz\n\ndefault allow := false"
            , source = InlineSource "package sentinel.authz\n\ndefault allow := false"
            }
      result <- addPolicy engine policy
      result `shouldBe` Right ()

      policies <- getPolicyInfo engine
      case policies of
        [(_, pkg)] -> pkg `shouldBe` "sentinel.authz"
        _ -> expectationFailure "Expected one policy"

  describe "evaluate" $ do
    it "evaluates a simple allow policy" $ pending

    it "evaluates a deny policy" $ pending

    it "handles missing rules gracefully" $ pending

{-# LANGUAGE OverloadedStrings #-}

module Test.Policy.Cedar (spec) where

import Test.Hspec
import Test.QuickCheck

import qualified Data.Map.Strict as Map
import Sentinel.Agent.Policy

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
            , engine = CedarEngine
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
            , engine = CedarEngine
            , content = "permit(principal, action, resource);"
            , source = InlineSource "permit(principal, action, resource);"
            }
      _ <- addPolicy engine policy
      clearPolicies engine
      policies <- getPolicyInfo engine
      policies `shouldBe` []

  describe "evaluate" $ do
    it "evaluates a simple allow policy" $ pending

    it "evaluates a deny policy" $ pending

    it "combines multiple policies correctly" $ pending

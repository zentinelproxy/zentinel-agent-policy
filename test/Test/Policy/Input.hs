{-# LANGUAGE OverloadedStrings #-}

module Test.Policy.Input (spec) where

import Test.Hspec
import Test.QuickCheck

import qualified Data.Map.Strict as Map
import Sentinel.Agent.Policy
import Sentinel.Agent.Policy.Input

spec :: Spec
spec = do
  describe "matchPath" $ do
    it "matches simple patterns" $ do
      let pattern = "/api/{resource_type}/{resource_id}"
          path = "/api/users/123"
          result = matchPath pattern path

      pmResourceType result `shouldBe` Just "users"
      pmResourceId result `shouldBe` Just "123"

    it "extracts all variables" $ do
      let pattern = "/v1/{version}/resources/{id}/sub/{subid}"
          path = "/v1/v2/resources/abc/sub/xyz"
          result = matchPath pattern path

      Map.lookup "version" (pmVariables result) `shouldBe` Just "v2"
      Map.lookup "id" (pmVariables result) `shouldBe` Just "abc"
      Map.lookup "subid" (pmVariables result) `shouldBe` Just "xyz"

    it "handles paths with no variables" $ do
      let pattern = "/api/static/path"
          path = "/api/static/path"
          result = matchPath pattern path

      pmVariables result `shouldBe` Map.empty

  describe "extractAction" $ do
    it "maps GET to read" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "GET"
      actionName action `shouldBe` "read"

    it "maps POST to create" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "POST"
      actionName action `shouldBe` "create"

    it "maps DELETE to delete" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "DELETE"
      actionName action `shouldBe` "delete"

    it "uses default for unknown methods" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "OPTIONS"
      actionName action `shouldBe` "access"

  describe "extractPrincipal" $ do
    it "extracts from header" $ do
      let mapping = HeaderPrincipal "X-User-ID"
          headers = Map.fromList [("x-user-id", "user-123")]
          principal = extractPrincipal mapping headers Map.empty

      principalId principal `shouldBe` "user-123"

    it "defaults to anonymous when header missing" $ do
      let mapping = HeaderPrincipal "X-User-ID"
          headers = Map.empty
          principal = extractPrincipal mapping headers Map.empty

      principalId principal `shouldBe` "anonymous"

    it "extracts from query param" $ do
      let mapping = QueryParamPrincipal "user"
          queryParams = Map.fromList [("user", "test-user")]
          principal = extractPrincipal mapping Map.empty queryParams

      principalId principal `shouldBe` "test-user"

-- Test fixtures
defaultActionMapping :: ActionMapping
defaultActionMapping = ActionMapping
  { getMapsTo = "read"
  , postMapsTo = "create"
  , putMapsTo = "update"
  , patchMapsTo = "update"
  , deleteMapsTo = "delete"
  , defaultAction = "access"
  }

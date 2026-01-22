{-# LANGUAGE OverloadedStrings #-}

module Test.Policy.Input (spec) where

import Test.Hspec
import Test.QuickCheck

import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text qualified as T

import Sentinel.Agent.Policy
import Sentinel.Agent.Policy.Input

spec :: Spec
spec = do
  describe "matchPath" $ do
    it "matches simple patterns" $ do
      let pattern = "/api/{resource_type}/{resource_id}"
          pathStr = "/api/users/123"
          result = matchPath pattern pathStr

      pmResourceType result `shouldBe` Just "users"
      pmResourceId result `shouldBe` Just "123"

    it "extracts all variables" $ do
      let pattern = "/v1/{version}/resources/{id}/sub/{subid}"
          pathStr = "/v1/v2/resources/abc/sub/xyz"
          result = matchPath pattern pathStr

      Map.lookup "version" (pmVariables result) `shouldBe` Just "v2"
      Map.lookup "id" (pmVariables result) `shouldBe` Just "abc"
      Map.lookup "subid" (pmVariables result) `shouldBe` Just "xyz"

    it "handles paths with no variables" $ do
      let pattern = "/api/static/path"
          pathStr = "/api/static/path"
          result = matchPath pattern pathStr

      pmVariables result `shouldBe` Map.empty

    it "handles empty paths" $ do
      let pattern = "/"
          pathStr = "/"
          result = matchPath pattern pathStr

      pmVariables result `shouldBe` Map.empty

    it "handles trailing slashes" $ do
      let pattern = "/api/{type}/"
          pathStr = "/api/users/"
          result = matchPath pattern pathStr

      Map.lookup "type" (pmVariables result) `shouldBe` Just "users"

  describe "extractAction" $ do
    it "maps GET to read" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "GET"
      actionName action `shouldBe` "read"
      method action `shouldBe` "GET"

    it "maps POST to create" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "POST"
      actionName action `shouldBe` "create"

    it "maps PUT to update" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "PUT"
      actionName action `shouldBe` "update"

    it "maps PATCH to update" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "PATCH"
      actionName action `shouldBe` "update"

    it "maps DELETE to delete" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "DELETE"
      actionName action `shouldBe` "delete"

    it "uses default for unknown methods" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "OPTIONS"
      actionName action `shouldBe` "access"

    it "is case insensitive" $ do
      let mapping = defaultActionMapping
          action = extractAction mapping "get"
      actionName action `shouldBe` "read"

  describe "extractPrincipal" $ do
    it "extracts from header" $ do
      let mapping = HeaderPrincipal "X-User-ID"
          headers = Map.fromList [("x-user-id", "user-123")]
          principal = extractPrincipal mapping headers Map.empty

      principalId principal `shouldBe` "user-123"
      principalType principal `shouldBe` Just "User"

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

    it "is case insensitive for headers" $ do
      let mapping = HeaderPrincipal "X-USER-ID"
          headers = Map.fromList [("x-user-id", "user-456")]
          principal = extractPrincipal mapping headers Map.empty

      principalId principal `shouldBe` "user-456"

  describe "extractResource" $ do
    it "extracts from path pattern" $ do
      let mapping = PathResource "/api/{resource_type}/{resource_id}"
          pathStr = "/api/documents/doc-123"
          resource = extractResource mapping pathStr Map.empty

      resourceId resource `shouldBe` "doc-123"
      resourceType resource `shouldBe` Just "documents"
      path resource `shouldBe` pathStr

    it "extracts from header" $ do
      let mapping = HeaderResource "X-Resource-ID"
          headers = Map.fromList [("x-resource-id", "resource-789")]
          resource = extractResource mapping "/some/path" headers

      resourceId resource `shouldBe` "resource-789"

    it "falls back to path when header missing" $ do
      let mapping = HeaderResource "X-Resource-ID"
          headers = Map.empty
          resource = extractResource mapping "/fallback/path" headers

      resourceId resource `shouldBe` "/fallback/path"

  describe "extractInput" $ do
    it "extracts complete policy input" $ do
      let mapping = InputMapping
            { principalMapping = HeaderPrincipal "X-User-ID"
            , resourceMapping = PathResource "/api/{resource_type}/{resource_id}"
            , actionMapping = defaultActionMapping
            }
          headers = Map.fromList [("x-user-id", "user-abc")]
          pathStr = "/api/files/file-xyz"
          input = extractInput mapping "GET" pathStr headers Map.empty

      principalId (principal input) `shouldBe` "user-abc"
      actionName (action input) `shouldBe` "read"
      resourceId (resource input) `shouldBe` "file-xyz"
      resourceType (resource input) `shouldBe` Just "files"

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

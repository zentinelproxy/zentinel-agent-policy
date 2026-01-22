-- |
-- Module      : Sentinel.Agent.Policy.Input
-- Description : Request to policy input mapping
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Functions for extracting policy input (principal, action, resource)
-- from incoming Sentinel agent requests.

module Sentinel.Agent.Policy.Input
  ( -- * Input Extraction
    extractInput
  , extractPrincipal
  , extractAction
  , extractResource

    -- * Path Pattern Matching
  , matchPath
  , PathMatch(..)
  ) where

import Data.Aeson (Value(..), object, (.=))
import qualified Data.Aeson as Aeson
import Data.CaseInsensitive (CI)
import qualified Data.CaseInsensitive as CI
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, listToMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Sentinel.Agent.Policy.Config
import Sentinel.Agent.Policy.Types

-- | Result of path pattern matching
data PathMatch = PathMatch
  { pmResourceType :: !(Maybe Text)
  , pmResourceId :: !(Maybe Text)
  , pmVariables :: !(Map Text Text)
  }
  deriving stock (Eq, Show)

-- | Extract complete policy input from a request
extractInput
  :: InputMapping
  -> Text           -- ^ HTTP method
  -> Text           -- ^ Request path
  -> Map Text Text  -- ^ Headers
  -> Map Text Text  -- ^ Query parameters
  -> PolicyInput
extractInput mapping method reqPath headers queryParams = PolicyInput
  { principal = extractPrincipal (principalMapping mapping) headers queryParams
  , action = extractAction (actionMapping mapping) method
  , resource = extractResource (resourceMapping mapping) reqPath headers
  , context = buildContext headers queryParams
  }

-- | Extract principal from request
extractPrincipal :: PrincipalMapping -> Map Text Text -> Map Text Text -> Principal
extractPrincipal mapping headers queryParams = case mapping of
  HeaderPrincipal headerName ->
    let pid = fromMaybe "anonymous" $ Map.lookup (T.toLower headerName) headers
    in Principal
        { principalId = pid
        , principalType = Just "User"
        , attributes = Map.empty
        }

  JWTClaimPrincipal claimName ->
    -- JWT should be pre-validated by auth agent
    -- Extract claim from X-JWT-Claims header if present
    let claims = fromMaybe "{}" $ Map.lookup "x-jwt-claims" headers
        pid = "jwt-user" -- TODO: Parse JWT claims JSON
    in Principal
        { principalId = pid
        , principalType = Just "User"
        , attributes = Map.empty
        }

  QueryParamPrincipal paramName ->
    let pid = fromMaybe "anonymous" $ Map.lookup paramName queryParams
    in Principal
        { principalId = pid
        , principalType = Just "User"
        , attributes = Map.empty
        }

-- | Extract action from HTTP method
extractAction :: ActionMapping -> Text -> Action
extractAction ActionMapping{..} method = Action
  { actionName = case T.toUpper method of
      "GET"    -> getMapsTo
      "POST"   -> postMapsTo
      "PUT"    -> putMapsTo
      "PATCH"  -> patchMapsTo
      "DELETE" -> deleteMapsTo
      _        -> defaultAction
  , method = T.toUpper method
  }

-- | Extract resource from request
extractResource :: ResourceMapping -> Text -> Map Text Text -> Resource
extractResource mapping reqPath headers = case mapping of
  PathResource pattern ->
    let PathMatch{..} = matchPath pattern reqPath
    in Resource
        { resourceId = fromMaybe reqPath pmResourceId
        , resourceType = pmResourceType
        , path = reqPath
        , attributes = Map.map String pmVariables
        }

  HeaderResource headerName ->
    let rid = fromMaybe reqPath $ Map.lookup (T.toLower headerName) headers
    in Resource
        { resourceId = rid
        , resourceType = Nothing
        , path = reqPath
        , attributes = Map.empty
        }

-- | Match a path against a pattern and extract variables
--
-- Pattern format: /api/{resource_type}/{resource_id}
-- Path: /api/users/123
-- Result: {resource_type: "users", resource_id: "123"}
matchPath :: Text -> Text -> PathMatch
matchPath pattern reqPath =
  let patternParts = filter (not . T.null) $ T.splitOn "/" pattern
      pathParts = filter (not . T.null) $ T.splitOn "/" reqPath
      vars = extractVariables patternParts pathParts
  in PathMatch
      { pmResourceType = Map.lookup "resource_type" vars
      , pmResourceId = Map.lookup "resource_id" vars
      , pmVariables = vars
      }

-- | Extract variables from pattern matching
extractVariables :: [Text] -> [Text] -> Map Text Text
extractVariables [] [] = Map.empty
extractVariables [] _ = Map.empty
extractVariables _ [] = Map.empty
extractVariables (p:ps) (v:vs)
  | isVariable p =
      let varName = T.dropEnd 1 $ T.drop 1 p  -- Remove { and }
      in Map.insert varName v $ extractVariables ps vs
  | otherwise = extractVariables ps vs

-- | Check if a pattern segment is a variable
isVariable :: Text -> Bool
isVariable t = T.isPrefixOf "{" t && T.isSuffixOf "}" t

-- | Build context map from headers and query params
buildContext :: Map Text Text -> Map Text Text -> Map Text Value
buildContext headers queryParams = Map.fromList
  [ ("headers", Object $ Aeson.toJSON headers)
  , ("query", Object $ Aeson.toJSON queryParams)
  ]

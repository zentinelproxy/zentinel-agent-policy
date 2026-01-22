-- |
-- Module      : Sentinel.Agent.Policy.Rego
-- Description : Rego/OPA policy engine implementation
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Rego policy language evaluator using OPA (Open Policy Agent).
-- Rego is a declarative query language designed for policy decisions.
--
-- See: https://www.openpolicyagent.org/docs/latest/policy-language/

module Sentinel.Agent.Policy.Rego
  ( -- * Rego Engine
    RegoEngine(..)
  , newRegoEngine

    -- * Rego Types
  , RegoPolicy(..)
  , RegoBundle(..)

    -- * Evaluation
  , evaluateRego
  ) where

import Control.Concurrent.STM
import Data.Aeson (Value(..), encode, object, (.=), FromJSON, ToJSON)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as LBS
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock.System (getSystemTime, systemNanoseconds)
import GHC.Generics (Generic)
import Sentinel.Agent.Policy.Engine
import Sentinel.Agent.Policy.Types

-- | A parsed Rego policy
data RegoPolicy = RegoPolicy
  { rpId :: !Text
  , rpPackage :: !Text
    -- ^ Rego package name (e.g., "sentinel.authz")
  , rpContent :: !Text
  , rpCompiled :: !Value
    -- ^ Compiled policy (placeholder)
  }
  deriving stock (Eq, Show, Generic)

-- | A Rego bundle from remote source
data RegoBundle = RegoBundle
  { rbId :: !Text
  , rbRevision :: !Text
  , rbPolicies :: ![RegoPolicy]
  , rbData :: !Value
    -- ^ Static data included with bundle
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | Rego policy engine state
data RegoEngine = RegoEngine
  { rePolicies :: !(TVar (Map Text RegoPolicy))
  , reData :: !(TVar Value)
    -- ^ Static data available to policies
  , reBundles :: !(TVar (Map Text RegoBundle))
  }

-- | Create a new Rego engine instance
newRegoEngine :: IO RegoEngine
newRegoEngine = RegoEngine
  <$> newTVarIO Map.empty
  <*> newTVarIO (Object mempty)
  <*> newTVarIO Map.empty

instance Engine RegoEngine where
  evaluate = evaluateRego

  engineType _ = RegoEngine

  addPolicy engine policy = do
    let pkg = extractPackage (content policy)
    let regoPolicy = RegoPolicy
          { rpId = policyId policy
          , rpPackage = pkg
          , rpContent = content policy
          , rpCompiled = Null -- TODO: Actually compile Rego policy
          }
    atomically $ modifyTVar' (rePolicies engine) $
      Map.insert (policyId policy) regoPolicy
    return $ Right ()

  clearPolicies engine = atomically $
    writeTVar (rePolicies engine) Map.empty

  getPolicyInfo engine = do
    policies <- readTVarIO (rePolicies engine)
    return $ Map.toList $ Map.map rpPackage policies

-- | Extract package name from Rego policy
extractPackage :: Text -> Text
extractPackage content =
  case filter ("package " `T.isPrefixOf`) (T.lines content) of
    (line:_) -> T.strip $ T.drop 8 line
    [] -> "unknown"

-- | Evaluate a policy input using Rego
evaluateRego :: RegoEngine -> PolicyInput -> IO (Either EngineError EvaluationResult)
evaluateRego engine input = do
  startTime <- getSystemTime
  policies <- readTVarIO (rePolicies engine)
  staticData <- readTVarIO (reData engine)

  -- Build OPA input from policy input
  let opaInput = buildOpaInput input staticData

  -- Evaluate all policies
  -- TODO: Use actual OPA evaluation (via embedded engine or HTTP)
  let results = evaluatePolicies (Map.elems policies) opaInput

  endTime <- getSystemTime
  let elapsedNs = fromIntegral (systemNanoseconds endTime - systemNanoseconds startTime)

  return $ Right EvaluationResult
    { decision = combineRegoDecisions results
    , reason = DecisionReason
        { matchedPolicies = map fst $ filter snd results
        , message = Just "Evaluated by Rego/OPA engine"
        , details = Just $ object
            [ "policies_checked" .= length policies
            , "input" .= opaInput
            ]
        }
    , evaluationTimeNs = elapsedNs
    , cached = False
    }

-- | Build OPA input from policy input and static data
buildOpaInput :: PolicyInput -> Value -> Value
buildOpaInput PolicyInput{..} staticData = object
  [ "principal" .= object
      [ "id" .= principalId principal
      , "type" .= principalType principal
      , "attributes" .= attributes principal
      ]
  , "action" .= actionName action
  , "method" .= method action
  , "resource" .= object
      [ "id" .= resourceId resource
      , "type" .= resourceType resource
      , "path" .= path resource
      , "attributes" .= attributes resource
      ]
  , "context" .= context
  , "data" .= staticData
  ]

-- | Evaluate policies against OPA input (placeholder implementation)
evaluatePolicies :: [RegoPolicy] -> Value -> [(Text, Bool)]
evaluatePolicies policies input =
  -- TODO: Implement actual Rego evaluation via OPA
  -- For now, return empty (no matches -> default deny)
  map (\p -> (rpId p, False)) policies

-- | Combine Rego policy decisions
-- Rego typically uses explicit allow/deny rules
combineRegoDecisions :: [(Text, Bool)] -> Decision
combineRegoDecisions results
  | any snd results = Allow
  | otherwise = Deny

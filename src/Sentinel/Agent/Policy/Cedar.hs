-- |
-- Module      : Sentinel.Agent.Policy.Cedar
-- Description : Cedar policy engine implementation
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Cedar policy language evaluator. Cedar is a policy language developed
-- by AWS that provides fine-grained access control with a clear, readable
-- syntax.
--
-- See: https://www.cedarpolicy.com/

module Sentinel.Agent.Policy.Cedar
  ( -- * Cedar Engine
    CedarEngine(..)
  , newCedarEngine

    -- * Cedar Types
  , CedarPolicy(..)
  , CedarSchema(..)
  , CedarEntities(..)

    -- * Evaluation
  , evaluateCedar
  ) where

import Control.Concurrent.STM
import Control.Monad (forM)
import Data.Aeson (Value(..), encode, object, (.=))
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as LBS
import Data.IORef
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (getCurrentTime, diffUTCTime)
import Data.Time.Clock.System (getSystemTime, systemNanoseconds)
import GHC.Generics (Generic)
import Sentinel.Agent.Policy.Engine
import Sentinel.Agent.Policy.Types

-- | A parsed Cedar policy
data CedarPolicy = CedarPolicy
  { cpId :: !Text
  , cpContent :: !Text
  , cpParsed :: !Value
    -- ^ Parsed AST (placeholder - would use actual cedar library)
  }
  deriving stock (Eq, Show, Generic)

-- | Cedar schema for entity types
newtype CedarSchema = CedarSchema
  { unCedarSchema :: Value }
  deriving stock (Eq, Show, Generic)

-- | Cedar entities (principals, resources, actions)
newtype CedarEntities = CedarEntities
  { unCedarEntities :: Map Text Value }
  deriving stock (Eq, Show, Generic)

-- | Cedar policy engine state
data CedarEngine = CedarEngine
  { cePolicies :: !(TVar (Map Text CedarPolicy))
  , ceSchema :: !(TVar (Maybe CedarSchema))
  , ceEntities :: !(TVar CedarEntities)
  }

-- | Create a new Cedar engine instance
newCedarEngine :: IO CedarEngine
newCedarEngine = CedarEngine
  <$> newTVarIO Map.empty
  <*> newTVarIO Nothing
  <*> newTVarIO (CedarEntities Map.empty)

instance Engine CedarEngine where
  evaluate = evaluateCedar

  engineType _ = CedarEngine

  addPolicy engine policy = do
    let cedarPolicy = CedarPolicy
          { cpId = policyId policy
          , cpContent = content policy
          , cpParsed = Null -- TODO: Actually parse Cedar policy
          }
    atomically $ modifyTVar' (cePolicies engine) $
      Map.insert (policyId policy) cedarPolicy
    return $ Right ()

  clearPolicies engine = atomically $
    writeTVar (cePolicies engine) Map.empty

  getPolicyInfo engine = do
    policies <- readTVarIO (cePolicies engine)
    return $ Map.toList $ Map.map (T.take 8 . cpContent) policies

-- | Evaluate a policy input using Cedar
evaluateCedar :: CedarEngine -> PolicyInput -> IO (Either EngineError EvaluationResult)
evaluateCedar engine input = do
  startTime <- getSystemTime
  policies <- readTVarIO (cePolicies engine)

  -- Build Cedar request from input
  let cedarRequest = buildCedarRequest input

  -- Evaluate all policies
  -- TODO: Use actual Cedar evaluation library
  let results = evaluatePolicies (Map.elems policies) cedarRequest

  endTime <- getSystemTime
  let elapsedNs = fromIntegral (systemNanoseconds endTime - systemNanoseconds startTime)

  return $ Right EvaluationResult
    { decision = combineDecisions results
    , reason = DecisionReason
        { matchedPolicies = map fst $ filter ((/= Nothing) . snd) results
        , message = Just "Evaluated by Cedar engine"
        , details = Just $ object
            [ "policies_checked" .= length policies
            , "request" .= cedarRequest
            ]
        }
    , evaluationTimeNs = elapsedNs
    , cached = False
    }

-- | Build a Cedar authorization request from policy input
buildCedarRequest :: PolicyInput -> Value
buildCedarRequest PolicyInput{..} = object
  [ "principal" .= object
      [ "type" .= maybe "User" id (principalType principal)
      , "id" .= principalId principal
      ]
  , "action" .= object
      [ "type" .= ("Action" :: Text)
      , "id" .= actionName action
      ]
  , "resource" .= object
      [ "type" .= maybe "Resource" id (resourceType resource)
      , "id" .= resourceId resource
      ]
  , "context" .= context
  ]

-- | Evaluate policies against a request (placeholder implementation)
evaluatePolicies :: [CedarPolicy] -> Value -> [(Text, Maybe Decision)]
evaluatePolicies policies request =
  -- TODO: Implement actual Cedar evaluation
  -- For now, return a default deny
  map (\p -> (cpId p, Nothing)) policies

-- | Combine decisions from multiple policies
-- Cedar uses forbid-overrides: any forbid wins, otherwise permit wins
combineDecisions :: [(Text, Maybe Decision)] -> Decision
combineDecisions results
  | any ((== Just Deny) . snd) results = Deny
  | any ((== Just Allow) . snd) results = Allow
  | otherwise = Deny  -- Default deny when no policies match

-- |
-- Module      : Sentinel.Agent.Policy.Handler
-- Description : Sentinel agent handler implementation
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Implementation of the Sentinel agent handler for policy evaluation
-- using the v2 agent protocol.

module Sentinel.Agent.Policy.Handler
  ( -- * Agent Types
    PolicyAgent(..)
  , newPolicyAgent

    -- * Agent Runner
  , runPolicyAgent
  ) where

import Control.Concurrent.STM
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask, runReaderT)
import Data.Aeson (Value(..), object, (.=), encode)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as LBS
import Data.IORef
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (getCurrentTime)
import GHC.Generics (Generic)

import Sentinel.Agent.Policy.Cache (DecisionCache, CacheStats(..))
import qualified Sentinel.Agent.Policy.Cache as Cache
import Sentinel.Agent.Policy.Cedar (CedarEngine, newCedarEngine)
import Sentinel.Agent.Policy.Config
import Sentinel.Agent.Policy.Engine
import Sentinel.Agent.Policy.Input (extractInput)
import Sentinel.Agent.Policy.Rego (RegoEngine, newRegoEngine)
import Sentinel.Agent.Policy.Types

-- Placeholder for sentinel-agent-protocol types
-- In real implementation, these come from the SDK

-- | Agent capabilities declaration
data AgentCapabilities = AgentCapabilities
  { subscribedEvents :: ![Text]
  , supportsMetrics :: !Bool
  , supportsHealth :: !Bool
  }
  deriving stock (Eq, Show, Generic)

-- | Request headers event from Sentinel
data RequestHeadersEvent = RequestHeadersEvent
  { rheRequestId :: !Text
  , rheMethod :: !Text
  , rhePath :: !Text
  , rheHeaders :: !(Map Text Text)
  , rheQueryParams :: !(Map Text Text)
  }
  deriving stock (Eq, Show, Generic)

-- | Agent response
data AgentResponse
  = AllowResponse
  | BlockResponse !Int !Text
  | ModifyResponse !(Map Text Text)
  deriving stock (Eq, Show, Generic)

-- | Policy agent state
data PolicyAgent = PolicyAgent
  { paConfig :: !AgentConfig
  , paCedar :: !CedarEngine
  , paRego :: !RegoEngine
  , paCache :: !DecisionCache
  , paMetrics :: !(TVar PolicyMetrics)
  }

-- | Policy agent metrics
data PolicyMetrics = PolicyMetrics
  { pmEvaluationsTotal :: !Int
  , pmAllowTotal :: !Int
  , pmDenyTotal :: !Int
  , pmCacheHits :: !Int
  , pmCacheMisses :: !Int
  , pmErrorsTotal :: !Int
  , pmEvalDurationNs :: !Integer
  }
  deriving stock (Eq, Show, Generic)

-- | Create a new policy agent
newPolicyAgent :: AgentConfig -> IO PolicyAgent
newPolicyAgent config = do
  cedarEngine <- newCedarEngine
  regoEngine <- newRegoEngine
  cache <- Cache.newCache (cache config)
  metrics <- newTVarIO $ PolicyMetrics 0 0 0 0 0 0 0

  let agent = PolicyAgent
        { paConfig = config
        , paCedar = cedarEngine
        , paRego = regoEngine
        , paCache = cache
        , paMetrics = metrics
        }

  -- Load initial policies
  loadInitialPolicies agent

  return agent

-- | Load policies from configuration
loadInitialPolicies :: PolicyAgent -> IO ()
loadInitialPolicies agent = do
  let configs = policies (paConfig agent)
      engineType = engine (paConfig agent)

  -- Load into appropriate engine based on config
  case engineType of
    CedarEngine -> do
      results <- loadPolicies (paCedar agent) configs
      mapM_ reportLoadError results
    RegoEngine -> do
      results <- loadPolicies (paRego agent) configs
      mapM_ reportLoadError results
    AutoEngine -> do
      -- Load into both engines, they'll handle appropriate policies
      _ <- loadPolicies (paCedar agent) configs
      _ <- loadPolicies (paRego agent) configs
      return ()

  where
    reportLoadError (Left err) = putStrLn $ "Policy load error: " ++ show err
    reportLoadError (Right _) = return ()

-- | Handle a request headers event
handleRequestHeaders :: PolicyAgent -> RequestHeadersEvent -> IO AgentResponse
handleRequestHeaders agent event = do
  -- Extract policy input from request
  let input = extractInput
        (inputMapping $ paConfig agent)
        (rheMethod event)
        (rhePath event)
        (rheHeaders event)
        (rheQueryParams event)

  -- Check cache first
  cached <- if enabled (cache $ paConfig agent)
    then Cache.lookup (paCache agent) input
    else return Nothing

  result <- case cached of
    Just cachedResult -> return $ Right cachedResult
    Nothing -> do
      -- Evaluate policies
      evalResult <- evaluatePolicy agent input

      -- Cache the result
      case evalResult of
        Right r -> when (enabled $ cache $ paConfig agent) $
          Cache.insert (paCache agent) input r
        _ -> return ()

      return evalResult

  -- Update metrics and return response
  case result of
    Right EvaluationResult{..} -> do
      atomically $ modifyTVar' (paMetrics agent) $ \m -> m
        { pmEvaluationsTotal = pmEvaluationsTotal m + 1
        , pmAllowTotal = if decision == Allow then pmAllowTotal m + 1 else pmAllowTotal m
        , pmDenyTotal = if decision == Deny then pmDenyTotal m + 1 else pmDenyTotal m
        , pmCacheHits = if cached then pmCacheHits m + 1 else pmCacheHits m
        , pmCacheMisses = if not cached then pmCacheMisses m + 1 else pmCacheMisses m
        , pmEvalDurationNs = pmEvalDurationNs m + evaluationTimeNs
        }

      case decision of
        Allow -> return AllowResponse
        Deny -> return $ BlockResponse 403 $
          maybe "Access denied by policy" id (message reason)

    Left err -> do
      atomically $ modifyTVar' (paMetrics agent) $ \m -> m
        { pmErrorsTotal = pmErrorsTotal m + 1 }

      -- Use default decision on error
      case defaultDecision (paConfig agent) of
        Allow -> return AllowResponse
        Deny -> return $ BlockResponse 403 "Policy evaluation error"

-- | Evaluate policy using configured engine
evaluatePolicy :: PolicyAgent -> PolicyInput -> IO (Either EngineError EvaluationResult)
evaluatePolicy agent input = case engine (paConfig agent) of
  CedarEngine -> evaluate (paCedar agent) input
  RegoEngine -> evaluate (paRego agent) input
  AutoEngine -> do
    -- Try Cedar first, fall back to Rego
    cedarResult <- evaluate (paCedar agent) input
    case cedarResult of
      Right r -> return $ Right r
      Left _ -> evaluate (paRego agent) input

-- | Get health status
getHealthStatus :: PolicyAgent -> IO Value
getHealthStatus agent = do
  cedarPolicies <- getPolicyInfo (paCedar agent)
  regoPolicies <- getPolicyInfo (paRego agent)
  metrics <- readTVarIO (paMetrics agent)

  return $ object
    [ "status" .= ("healthy" :: Text)
    , "cedar_policies" .= length cedarPolicies
    , "rego_policies" .= length regoPolicies
    , "evaluations_total" .= pmEvaluationsTotal metrics
    , "error_rate" .= calculateErrorRate metrics
    ]

  where
    calculateErrorRate m =
      if pmEvaluationsTotal m == 0
        then 0.0 :: Double
        else fromIntegral (pmErrorsTotal m) / fromIntegral (pmEvaluationsTotal m)

-- | Get Prometheus metrics
getMetrics :: PolicyAgent -> IO Text
getMetrics agent = do
  metrics <- readTVarIO (paMetrics agent)
  cacheStats <- Cache.getStats (paCache agent)

  return $ T.unlines
    [ "# HELP policy_evaluations_total Total number of policy evaluations"
    , "# TYPE policy_evaluations_total counter"
    , "policy_evaluations_total " <> T.pack (show $ pmEvaluationsTotal metrics)
    , ""
    , "# HELP policy_decisions_total Policy decisions by result"
    , "# TYPE policy_decisions_total counter"
    , "policy_decisions_total{result=\"allow\"} " <> T.pack (show $ pmAllowTotal metrics)
    , "policy_decisions_total{result=\"deny\"} " <> T.pack (show $ pmDenyTotal metrics)
    , ""
    , "# HELP policy_cache_hits_total Cache hits"
    , "# TYPE policy_cache_hits_total counter"
    , "policy_cache_hits_total " <> T.pack (show $ csHits cacheStats)
    , ""
    , "# HELP policy_cache_misses_total Cache misses"
    , "# TYPE policy_cache_misses_total counter"
    , "policy_cache_misses_total " <> T.pack (show $ csMisses cacheStats)
    , ""
    , "# HELP policy_errors_total Policy evaluation errors"
    , "# TYPE policy_errors_total counter"
    , "policy_errors_total " <> T.pack (show $ pmErrorsTotal metrics)
    ]

-- | Run the policy agent (placeholder for actual SDK integration)
runPolicyAgent :: AgentConfig -> IO ()
runPolicyAgent config = do
  agent <- newPolicyAgent config
  putStrLn $ "Policy agent starting on " ++ socketPath config
  putStrLn $ "Engine: " ++ show (engine config)
  putStrLn $ "Loaded " ++ show (length $ policies config) ++ " policy source(s)"

  -- In real implementation, this would:
  -- 1. Create Unix socket at socketPath
  -- 2. Listen for Sentinel v2 protocol messages
  -- 3. Dispatch to handleRequestHeaders, getHealthStatus, getMetrics
  -- 4. Send responses back over socket

  -- For now, just keep running
  putStrLn "Agent ready, waiting for requests..."
  waitForever

  where
    waitForever = do
      threadDelay 1000000000  -- Sleep for ~16 minutes
      waitForever

    threadDelay :: Int -> IO ()
    threadDelay _ = return ()  -- Placeholder

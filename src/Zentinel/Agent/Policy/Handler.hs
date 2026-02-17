-- |
-- Module      : Zentinel.Agent.Policy.Handler
-- Description : Zentinel agent handler implementation
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Implementation of the Zentinel agent handler for policy evaluation
-- using the v2 agent protocol.

module Zentinel.Agent.Policy.Handler
  ( -- * Agent Types
    PolicyAgent(..)
  , newPolicyAgent

    -- * Agent Runner
  , runPolicyAgent
  ) where

import Control.Concurrent.STM
import Control.Monad (when, forM_)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (Value(..))
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as LBS
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HM
import Data.IORef
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word32, Word64)
import GHC.Generics (Generic)

import Zentinel.Agent.Policy.Protocol
import Zentinel.Agent.Policy.Cache (DecisionCache, CacheStats(..))
import qualified Zentinel.Agent.Policy.Cache as Cache
import Zentinel.Agent.Policy.Cedar (CedarEngine, newCedarEngine)
import Zentinel.Agent.Policy.Config
import qualified Zentinel.Agent.Policy.Config as Config
import Zentinel.Agent.Policy.Engine
import Zentinel.Agent.Policy.Input (extractInput)
import Zentinel.Agent.Policy.Rego (RegoEngine, newRegoEngine)
import Zentinel.Agent.Policy.Types hiding (Decision(..), policies, engine)
import qualified Zentinel.Agent.Policy.Types as Policy

-- | Policy agent state
data PolicyAgent = PolicyAgent
  { paConfig :: !AgentConfig
  , paCedar :: !CedarEngine
  , paRego :: !RegoEngine
  , paCache :: !DecisionCache
  , paEvaluationsTotal :: !(IORef Word64)
  , paAllowTotal :: !(IORef Word64)
  , paDenyTotal :: !(IORef Word64)
  , paErrorsTotal :: !(IORef Word64)
  , paInFlight :: !(IORef Word32)
  , paEvalDurationNs :: !(IORef Word64)
  }

-- | Create a new policy agent
newPolicyAgent :: AgentConfig -> IO PolicyAgent
newPolicyAgent config = do
  cedarEngine <- newCedarEngine
  regoEngine <- newRegoEngine
  cacheInstance <- Cache.newCache (Zentinel.Agent.Policy.Config.cache config)

  agent <- PolicyAgent config cedarEngine regoEngine cacheInstance
    <$> newIORef 0
    <*> newIORef 0
    <*> newIORef 0
    <*> newIORef 0
    <*> newIORef 0
    <*> newIORef 0

  -- Load initial policies
  loadInitialPolicies agent

  return agent

-- | Load policies from configuration
loadInitialPolicies :: PolicyAgent -> IO ()
loadInitialPolicies agent = do
  let configs = policies (paConfig agent)
      engineType' = engine (paConfig agent)

  forM_ configs $ \policyConfig -> do
    case pcType policyConfig of
      "file" -> case pcPath policyConfig of
        Just filePath -> do
          content <- T.pack <$> readFile filePath
          let eng = detectEngineFromPath filePath
              policy = Policy
                { policyId = T.pack filePath
                , Policy.engine = eng
                , Policy.content = content
                , Policy.source = FileSource filePath
                }
          loadToEngine agent engineType' policy
        Nothing -> putStrLn "Warning: file policy missing path"

      "inline" -> case pcContent policyConfig of
        Just content -> do
          let policy = Policy
                { policyId = "inline-policy"
                , Policy.engine = engineType'
                , Policy.content = content
                , Policy.source = InlineSource content
                }
          loadToEngine agent engineType' policy
        Nothing -> putStrLn "Warning: inline policy missing content"

      other -> putStrLn $ "Warning: unknown policy type: " <> T.unpack other

-- | Detect engine from file extension
detectEngineFromPath :: FilePath -> PolicyEngine
detectEngineFromPath path
  | ".cedar" `T.isSuffixOf` T.pack path = CedarEngine
  | ".rego" `T.isSuffixOf` T.pack path = RegoEngine
  | otherwise = AutoEngine

-- | Load a policy to the appropriate engine
loadToEngine :: PolicyAgent -> PolicyEngine -> Policy -> IO ()
loadToEngine agent engineType' policy = case engineType' of
  CedarEngine -> do
    result <- addPolicy (paCedar agent) policy
    reportResult "Cedar" result
  RegoEngine -> do
    result <- addPolicy (paRego agent) policy
    reportResult "Rego" result
  AutoEngine -> do
    case Policy.engine policy of
      CedarEngine -> do
        result <- addPolicy (paCedar agent) policy
        reportResult "Cedar" result
      RegoEngine -> do
        result <- addPolicy (paRego agent) policy
        reportResult "Rego" result
      AutoEngine -> do
        if "package " `T.isInfixOf` Policy.content policy
          then do
            result <- addPolicy (paRego agent) policy
            reportResult "Rego" result
          else do
            result <- addPolicy (paCedar agent) policy
            reportResult "Cedar" result
  where
    reportResult name (Left err) =
      putStrLn $ "Error loading " <> name <> " policy: " <> show err
    reportResult name (Right _) =
      putStrLn $ "Loaded policy into " <> name <> " engine"

-- | Handle request headers
handleRequestHeaders :: PolicyAgent -> RequestHeadersEvent -> IO AgentResponse
handleRequestHeaders agent event = do
  atomicModifyIORef' (paInFlight agent) (\n -> (n + 1, ()))

  let uri = reqHdrUri event
      reqMethod = reqHdrMethod event
      headers = reqHdrHeaders event

  -- Convert headers to Map Text Text
  let headerMap = Map.fromList
        [ (T.toLower k, v) | (k, v) <- HM.toList headers ]

  -- Extract policy input from request
  let policyInput = extractInput
        (inputMapping $ paConfig agent)
        reqMethod
        uri
        headerMap
        Map.empty

  -- Check cache first
  cached <- if enabled (Zentinel.Agent.Policy.Config.cache $ paConfig agent)
    then Cache.lookup (paCache agent) policyInput
    else return Nothing

  result <- case cached of
    Just cachedResult -> return $ Right cachedResult
    Nothing -> do
      evalResult <- evaluatePolicy agent policyInput
      case evalResult of
        Right r -> when (enabled $ Zentinel.Agent.Policy.Config.cache $ paConfig agent) $
          Cache.insert (paCache agent) policyInput r
        _ -> return ()
      return evalResult

  -- Update metrics and return response
  atomicModifyIORef' (paInFlight agent) (\n -> (max 0 (n - 1), ()))

  case result of
    Right evalResult -> do
      atomicModifyIORef' (paEvaluationsTotal agent) (\n -> (n + 1, ()))
      atomicModifyIORef' (paEvalDurationNs agent)
        (\n -> (n + fromIntegral (evaluationTimeNs evalResult), ()))

      case decision evalResult of
        Policy.Allow -> do
          atomicModifyIORef' (paAllowTotal agent) (\n -> (n + 1, ()))
          return allow
        Policy.Deny -> do
          atomicModifyIORef' (paDenyTotal agent) (\n -> (n + 1, ()))
          let msg = maybe "Access denied by policy" id (message $ reason evalResult)
          return $ block 403 msg

    Left _ -> do
      atomicModifyIORef' (paErrorsTotal agent) (\n -> (n + 1, ()))
      case defaultDecision (paConfig agent) of
        Policy.Allow -> return allow
        Policy.Deny -> return $ block 403 "Policy evaluation error"

-- | Get health status
getHealthStatus :: PolicyAgent -> IO HealthStatus
getHealthStatus agent = do
  timestamp <- getCurrentTimeMs
  inFlight <- readIORef (paInFlight agent)
  evaluations <- readIORef (paEvaluationsTotal agent)
  denied <- readIORef (paDenyTotal agent)
  errors <- readIORef (paErrorsTotal agent)
  durationNs <- readIORef (paEvalDurationNs agent)

  let avgLatencyMs = if evaluations > 0
        then fromIntegral durationNs / fromIntegral evaluations / 1000000
        else 0.0

  let load = LoadMetrics
        { loadInFlight = inFlight
        , loadQueueDepth = 0
        , loadAvgLatencyMs = avgLatencyMs
        , loadRequestsProcessed = evaluations
        , loadRequestsRejected = denied
        }

  let status = if fromIntegral errors > evaluations `div` 10 || inFlight > 80
        then "degraded"
        else "healthy"

  return HealthStatus
    { hsAgentId = "policy-agent-001"
    , hsStatus = status
    , hsTimestampMs = timestamp
    , hsLoad = Just load
    }

-- | Get metrics report
getMetricsReport :: PolicyAgent -> IO (Maybe MetricsReport)
getMetricsReport agent = do
  timestamp <- getCurrentTimeMs
  evaluations <- readIORef (paEvaluationsTotal agent)
  allowed <- readIORef (paAllowTotal agent)
  denied <- readIORef (paDenyTotal agent)
  errors <- readIORef (paErrorsTotal agent)
  inFlight <- readIORef (paInFlight agent)
  cacheStats <- Cache.getStats (paCache agent)

  return $ Just MetricsReport
    { mrAgentId = "policy-agent-001"
    , mrTimestampMs = timestamp
    , mrCounters =
        [ counterMetric "policy_evaluations_total" evaluations
        , counterMetric "policy_allow_total" allowed
        , counterMetric "policy_deny_total" denied
        , counterMetric "policy_cache_hits_total" (fromIntegral $ csHits cacheStats)
        , counterMetric "policy_cache_misses_total" (fromIntegral $ csMisses cacheStats)
        , counterMetric "policy_errors_total" errors
        ]
    , mrGauges =
        [ gaugeMetric "policy_in_flight" (fromIntegral inFlight)
        , gaugeMetric "policy_cache_entries" (fromIntegral $ csEntries cacheStats)
        ]
    }

-- | Get current time in milliseconds
getCurrentTimeMs :: IO Word64
getCurrentTimeMs = do
  t <- getPOSIXTime
  return $ round (t * 1000)

-- | Evaluate policy using configured engine
evaluatePolicy :: PolicyAgent -> PolicyInput -> IO (Either EngineError EvaluationResult)
evaluatePolicy agent input = case engine (paConfig agent) of
  CedarEngine -> Zentinel.Agent.Policy.Engine.evaluate (paCedar agent) input
  RegoEngine -> Zentinel.Agent.Policy.Engine.evaluate (paRego agent) input
  AutoEngine -> do
    cedarResult <- Zentinel.Agent.Policy.Engine.evaluate (paCedar agent) input
    case cedarResult of
      Right r -> return $ Right r
      Left _ -> Zentinel.Agent.Policy.Engine.evaluate (paRego agent) input

-- | Run the policy agent
runPolicyAgent :: AgentConfig -> IO ()
runPolicyAgent config = do
  agent <- newPolicyAgent config
  putStrLn $ "Policy agent starting on " ++ socketPath config
  putStrLn $ "Engine: " ++ show (engine config)
  putStrLn $ "Policies: " ++ show (length $ policies config)

  let serverConfig = defaultServerConfig
        { scSocketPath = Just (socketPath config)
        , scLogLevel = case logLevel config of
            "debug" -> Debug
            "warn"  -> Warn
            "error" -> Error
            _       -> Info
        }

  let handler = AgentHandler
        { ahCapabilities = return $ defaultCapabilities "policy-agent"
        , ahOnRequestHeaders = handleRequestHeaders agent
        , ahHealthStatus = getHealthStatus agent
        , ahMetricsReport = getMetricsReport agent
        }

  runAgent serverConfig handler

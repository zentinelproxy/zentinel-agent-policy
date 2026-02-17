-- |
-- Module      : Zentinel.Agent.Policy.Rego
-- Description : Rego/OPA policy engine implementation
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Rego policy language evaluator using the OPA (Open Policy Agent) CLI.
-- Rego is a declarative query language designed for policy decisions.
--
-- This implementation shells out to the `opa` CLI tool for evaluation.
-- For production use, consider embedding OPA or using its REST API.
--
-- See: https://www.openpolicyagent.org/docs/latest/policy-language/

module Zentinel.Agent.Policy.Rego
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
import Control.Exception (try, SomeException)
import Data.Aeson (Value(..), encode, decode, object, (.=), (.:), (.:?), FromJSON, ToJSON)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LBS8
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, catMaybes)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import Data.Time.Clock.System (getSystemTime, systemNanoseconds, systemSeconds)
import GHC.Generics (Generic)
import System.Exit (ExitCode(..))
import System.IO.Temp (withSystemTempDirectory)
import System.Process (readProcessWithExitCode)

import qualified Data.Vector as V
import Zentinel.Agent.Policy.Engine
import Zentinel.Agent.Policy.Types hiding (RegoEngine)
import qualified Zentinel.Agent.Policy.Types as Types

-- | A parsed Rego policy
data RegoPolicy = RegoPolicy
  { rpId :: !Text
  , rpPackage :: !Text
    -- ^ Rego package name (e.g., "zentinel.authz")
  , rpContent :: !Text
  , rpFilePath :: !(Maybe FilePath)
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

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
  , reQueryPath :: !(TVar Text)
    -- ^ The Rego query path for evaluation (e.g., "data.zentinel.authz.allow")
  }

-- | Create a new Rego engine instance
newRegoEngine :: IO RegoEngine
newRegoEngine = RegoEngine
  <$> newTVarIO Map.empty
  <*> newTVarIO (Object mempty)
  <*> newTVarIO Map.empty
  <*> newTVarIO "data.zentinel.authz.allow"

instance Engine RegoEngine where
  evaluate = evaluateRego

  engineType _ = Types.RegoEngine

  addPolicy engine policy = do
    let pkg = extractPackage (content policy)
    let regoPolicy = RegoPolicy
          { rpId = policyId policy
          , rpPackage = pkg
          , rpContent = content policy
          , rpFilePath = case source policy of
              FileSource fp -> Just fp
              _ -> Nothing
          }
    atomically $ modifyTVar' (rePolicies engine) $
      Map.insert (policyId policy) regoPolicy

    -- Auto-detect query path from package
    when (pkg /= "unknown") $ do
      atomically $ writeTVar (reQueryPath engine) $
        "data." <> pkg <> ".allow"

    return $ Right ()
    where
      when cond action = if cond then action else return ()

  clearPolicies engine = atomically $
    writeTVar (rePolicies engine) Map.empty

  getPolicyInfo engine = do
    policies <- readTVarIO (rePolicies engine)
    return $ Map.toList $ Map.map rpPackage policies

-- | Extract package name from Rego policy
extractPackage :: Text -> Text
extractPackage policyContent =
  case filter ("package " `T.isPrefixOf`) (T.lines policyContent) of
    (line:_) -> T.strip $ T.drop 8 line
    [] -> "unknown"

-- | Set static data for policies
setData :: RegoEngine -> Value -> IO ()
setData engine dataValue =
  atomically $ writeTVar (reData engine) dataValue

-- | Set the query path for evaluation
setQueryPath :: RegoEngine -> Text -> IO ()
setQueryPath engine queryPath =
  atomically $ writeTVar (reQueryPath engine) queryPath

-- | Evaluate a policy input using OPA CLI
evaluateRego :: RegoEngine -> PolicyInput -> IO (Either EngineError EvaluationResult)
evaluateRego engine input = do
  startTime <- getSystemTime
  policies <- readTVarIO (rePolicies engine)
  staticData <- readTVarIO (reData engine)
  queryPath <- readTVarIO (reQueryPath engine)

  if Map.null policies
    then return $ Left $ EvaluationError "No Rego policies loaded"
    else do
      -- Combine all policies
      let allPolicies = map rpContent $ Map.elems policies

      -- Build OPA input
      let opaInput = buildOpaInput input staticData

      -- Run OPA eval
      result <- runOpaEval allPolicies opaInput queryPath

      endTime <- getSystemTime
      let elapsedNs = fromIntegral (systemSeconds endTime - systemSeconds startTime) * 1000000000
                    + fromIntegral (systemNanoseconds endTime - systemNanoseconds startTime)

      case result of
        Left err -> return $ Left err
        Right (decision, diagnostics) -> return $ Right EvaluationResult
          { decision = decision
          , reason = DecisionReason
              { matchedPolicies = diagnostics
              , message = Just $ if decision == Allow
                  then "Request permitted by Rego policy"
                  else "Request denied by Rego policy"
              , details = Nothing
              }
          , evaluationTimeNs = elapsedNs
          , cached = False
          }

-- | Build OPA input from policy input and static data
buildOpaInput :: PolicyInput -> Value -> Value
buildOpaInput PolicyInput{..} staticData =
  let Principal{attributes = principalAttrs} = principal
      Resource{attributes = resourceAttrs, path = resourcePath} = resource
      Action{method = actionMethod} = action
  in object
    [ "principal" .= object
        [ "id" .= principalId principal
        , "type" .= principalType principal
        , "attributes" .= principalAttrs
        ]
    , "action" .= actionName action
    , "method" .= actionMethod
    , "resource" .= object
        [ "id" .= resourceId resource
        , "type" .= resourceType resource
        , "path" .= resourcePath
        , "attributes" .= resourceAttrs
        ]
    , "context" .= context
    , "data" .= staticData
    ]

-- | Run OPA eval command
runOpaEval
  :: [Text]         -- ^ Policy contents
  -> Value          -- ^ Input JSON
  -> Text           -- ^ Query path (e.g., "data.zentinel.authz.allow")
  -> IO (Either EngineError (Decision, [Text]))
runOpaEval policyContents input queryPath = do
  withSystemTempDirectory "opa-eval" $ \tmpDir -> do
    -- Write policy files
    policyPaths <- mapM (writePolicyFile tmpDir) (zip [1..] policyContents)

    -- Write input file
    let inputPath = tmpDir <> "/input.json"
    LBS.writeFile inputPath (encode input)

    -- Build command arguments
    let args = ["eval"]
          ++ concatMap (\p -> ["-d", p]) policyPaths
          ++ ["-i", inputPath]
          ++ ["--format", "json"]
          ++ [T.unpack queryPath]

    -- Run OPA CLI
    result <- try $ readProcessWithExitCode "opa" args ""

    case result of
      Left (err :: SomeException) ->
        return $ Left $ EvaluationError $
          "Failed to execute opa CLI: " <> T.pack (show err)

      Right (exitCode, stdout, stderr) -> do
        case exitCode of
          ExitSuccess -> parseOpaOutput stdout
          ExitFailure code ->
            return $ Left $ EvaluationError $
              "OPA CLI error (exit " <> T.pack (show code) <> "): "
              <> T.pack stderr <> "\nstdout: " <> T.pack stdout

-- | Write a policy file and return its path
writePolicyFile :: FilePath -> (Int, Text) -> IO FilePath
writePolicyFile tmpDir (idx, policyContent) = do
  let path = tmpDir <> "/policy" <> show idx <> ".rego"
  TIO.writeFile path policyContent
  return path

-- | Parse OPA eval JSON output
--
-- OPA eval with --format json returns:
-- {
--   "result": [
--     {
--       "expressions": [
--         {
--           "value": true,  // or false
--           "text": "data.zentinel.authz.allow",
--           "location": {...}
--         }
--       ]
--     }
--   ]
-- }
parseOpaOutput :: String -> IO (Either EngineError (Decision, [Text]))
parseOpaOutput output = do
  case decode (LBS8.pack output) of
    Nothing ->
      return $ Left $ EvaluationError $
        "Failed to parse OPA JSON output: " <> T.pack output

    Just (Object obj) -> do
      case KM.lookup "result" obj of
        Just (Array results) | not (V.null results) -> do
          -- Get first result
          case V.head results of
            Object resultObj ->
              case KM.lookup "expressions" resultObj of
                Just (Array exprs) | not (V.null exprs) -> do
                  case V.head exprs of
                    Object exprObj ->
                      case KM.lookup "value" exprObj of
                        Just (Bool True) ->
                          return $ Right (Allow, ["allow"])
                        Just (Bool False) ->
                          return $ Right (Deny, ["deny"])
                        Just other ->
                          -- Non-boolean result, interpret as deny
                          return $ Right (Deny, ["non-boolean-result"])
                        Nothing ->
                          return $ Left $ EvaluationError "No value in expression"
                    _ -> return $ Left $ EvaluationError "Invalid expression format"
                _ -> return $ Left $ EvaluationError "No expressions in result"
            _ -> return $ Left $ EvaluationError "Invalid result format"

        Just (Array results) ->
          -- Empty results means the query returned undefined/no match
          return $ Right (Deny, ["undefined"])

        _ -> return $ Left $ EvaluationError $
          "No result in OPA output: " <> T.pack output

    Just _ ->
      return $ Left $ EvaluationError $
        "OPA output is not a JSON object: " <> T.pack output

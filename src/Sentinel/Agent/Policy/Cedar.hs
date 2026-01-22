-- |
-- Module      : Sentinel.Agent.Policy.Cedar
-- Description : Cedar policy engine implementation
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Cedar policy language evaluator using the Cedar CLI.
-- Cedar is a policy language developed by AWS that provides
-- fine-grained access control with a clear, readable syntax.
--
-- This implementation shells out to the `cedar` CLI tool for evaluation.
-- For production use, consider using FFI bindings to the Rust library.
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
import Control.Exception (try, SomeException)
import Control.Monad (forM, when)
import Data.Aeson (Value(..), encode, decode, object, (.=), (.:), (.:?))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LBS8
import Data.IORef
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, catMaybes)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import Data.Time.Clock (getCurrentTime)
import Data.Time.Clock.System (getSystemTime, systemNanoseconds, systemSeconds)
import GHC.Generics (Generic)
import System.Exit (ExitCode(..))
import System.IO (hClose)
import System.IO.Temp (withSystemTempDirectory, withSystemTempFile)
import System.Process (readProcessWithExitCode, CreateProcess(..), proc, withCreateProcess, StdStream(..), waitForProcess)

import Sentinel.Agent.Policy.Engine
import Sentinel.Agent.Policy.Types hiding (CedarEngine)
import qualified Sentinel.Agent.Policy.Types as Types

-- | A parsed Cedar policy
data CedarPolicy = CedarPolicy
  { cpId :: !Text
  , cpContent :: !Text
  , cpFilePath :: !(Maybe FilePath)
    -- ^ Path to policy file if loaded from file
  }
  deriving stock (Eq, Show, Generic)

-- | Cedar schema for entity types (optional)
newtype CedarSchema = CedarSchema
  { unCedarSchema :: Text }
  deriving stock (Eq, Show, Generic)

-- | Cedar entities (principals, resources, actions)
newtype CedarEntities = CedarEntities
  { unCedarEntities :: Value }
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
  <*> newTVarIO (CedarEntities (Array mempty))

instance Engine CedarEngine where
  evaluate = evaluateCedar

  engineType _ = Types.CedarEngine

  addPolicy engine policy = do
    let cedarPolicy = CedarPolicy
          { cpId = policyId policy
          , cpContent = content policy
          , cpFilePath = case source policy of
              FileSource fp -> Just fp
              _ -> Nothing
          }
    atomically $ modifyTVar' (cePolicies engine) $
      Map.insert (policyId policy) cedarPolicy
    return $ Right ()

  clearPolicies engine = atomically $
    writeTVar (cePolicies engine) Map.empty

  getPolicyInfo engine = do
    policies <- readTVarIO (cePolicies engine)
    return $ Map.toList $ Map.map (T.take 40 . cpContent) policies

-- | Evaluate a policy input using Cedar CLI
evaluateCedar :: CedarEngine -> PolicyInput -> IO (Either EngineError EvaluationResult)
evaluateCedar engine input = do
  startTime <- getSystemTime
  policies <- readTVarIO (cePolicies engine)
  entities <- readTVarIO (ceEntities engine)
  mSchema <- readTVarIO (ceSchema engine)

  if Map.null policies
    then return $ Left $ EvaluationError "No Cedar policies loaded"
    else do
      -- Combine all policies into one text
      let allPolicies = T.unlines $ map cpContent $ Map.elems policies

      -- Build Cedar authorization request
      let cedarRequest = buildCedarAuthRequest input

      -- Run cedar CLI
      result <- runCedarAuthorize allPolicies cedarRequest (unCedarEntities entities) mSchema

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
                  then "Request permitted by Cedar policy"
                  else "Request denied by Cedar policy"
              , details = Nothing
              }
          , evaluationTimeNs = elapsedNs
          , cached = False
          }

-- | Build a Cedar authorization request JSON
buildCedarAuthRequest :: PolicyInput -> Value
buildCedarAuthRequest PolicyInput{..} = object
  [ "principal" .= formatCedarEntity
      (fromMaybe "User" (principalType principal))
      (principalId principal)
  , "action" .= formatCedarEntity "Action" (actionName action)
  , "resource" .= formatCedarEntity
      (fromMaybe "Resource" (resourceType resource))
      (resourceId resource)
  , "context" .= context
  ]

-- | Format a Cedar entity reference
formatCedarEntity :: Text -> Text -> Text
formatCedarEntity entityType entityId =
  entityType <> "::\"" <> entityId <> "\""

-- | Run cedar authorize command
runCedarAuthorize
  :: Text           -- ^ Policy content
  -> Value          -- ^ Request JSON
  -> Value          -- ^ Entities JSON
  -> Maybe CedarSchema  -- ^ Optional schema
  -> IO (Either EngineError (Decision, [Text]))
runCedarAuthorize policyContent request entities mSchema = do
  withSystemTempDirectory "cedar-eval" $ \tmpDir -> do
    -- Write policy file
    let policyPath = tmpDir <> "/policies.cedar"
    TIO.writeFile policyPath policyContent

    -- Write entities file
    let entitiesPath = tmpDir <> "/entities.json"
    LBS.writeFile entitiesPath (encode entities)

    -- Write request file
    let requestPath = tmpDir <> "/request.json"
    LBS.writeFile requestPath (encode request)

    -- Build command arguments
    let args = ["authorize"]
          ++ ["--policies", policyPath]
          ++ ["--entities", entitiesPath]
          ++ ["--request-json", requestPath]
          ++ maybe [] (\s -> ["--schema", tmpDir <> "/schema.cedarschema"]) mSchema

    -- Write schema if provided
    case mSchema of
      Just (CedarSchema schemaContent) ->
        TIO.writeFile (tmpDir <> "/schema.cedarschema") schemaContent
      Nothing -> return ()

    -- Run cedar CLI
    result <- try $ readProcessWithExitCode "cedar" args ""

    case result of
      Left (err :: SomeException) ->
        return $ Left $ EvaluationError $
          "Failed to execute cedar CLI: " <> T.pack (show err)

      Right (exitCode, stdout, stderr) -> do
        case exitCode of
          ExitSuccess -> parseCedarOutput stdout
          ExitFailure code ->
            -- Cedar returns exit code 2 for DENY, 0 for ALLOW
            if code == 2
              then parseCedarOutput stdout
              else return $ Left $ EvaluationError $
                "Cedar CLI error (exit " <> T.pack (show code) <> "): "
                <> T.pack stderr

-- | Parse cedar authorize output
parseCedarOutput :: String -> IO (Either EngineError (Decision, [Text]))
parseCedarOutput output = do
  let outputText = T.pack output
      outputLower = T.toLower outputText

  -- Cedar CLI outputs "ALLOW" or "DENY"
  if "allow" `T.isInfixOf` outputLower
    then return $ Right (Allow, extractDiagnostics outputText)
    else if "deny" `T.isInfixOf` outputLower
      then return $ Right (Deny, extractDiagnostics outputText)
      else return $ Left $ EvaluationError $
        "Could not parse Cedar output: " <> outputText

-- | Extract diagnostic information from Cedar output
extractDiagnostics :: Text -> [Text]
extractDiagnostics output =
  -- Extract policy IDs that contributed to the decision
  -- Cedar output format varies, so we do basic extraction
  let lines' = T.lines output
      policyLines = filter (\l -> "policy" `T.isInfixOf` T.toLower l) lines'
  in if null policyLines
       then ["default"]
       else policyLines

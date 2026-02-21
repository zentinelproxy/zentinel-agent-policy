-- |
-- Module      : Zentinel.Agent.Policy.Engine
-- Description : Policy engine interface and factory
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Abstract interface for policy engines and factory for creating
-- the appropriate engine based on configuration.

module Zentinel.Agent.Policy.Engine
  ( -- * Engine Interface
    Engine(..)
  , EngineError(..)

    -- * Engine Creation
  , createEngine
  , detectEngine

    -- * Engine Operations
  , loadPolicies
  , reloadPolicies
  ) where

import Control.Exception (Exception)
import Data.Text (Text)
import qualified Data.Text as T
import Zentinel.Agent.Policy.Config (PolicyConfig(..))
import Zentinel.Agent.Policy.Types
import qualified Zentinel.Agent.Policy.Cedar as Cedar
import qualified Zentinel.Agent.Policy.Rego as Rego

-- | Errors that can occur during policy evaluation
data EngineError
  = ParseError !Text
    -- ^ Failed to parse policy
  | EvaluationError !Text
    -- ^ Error during evaluation
  | LoadError !Text
    -- ^ Failed to load policy from source
  | UnsupportedEngine !Text
    -- ^ Requested engine not supported
  deriving stock (Eq, Show)

instance Exception EngineError

-- | Abstract interface for policy engines
class Engine e where
  -- | Evaluate a policy input and return a decision
  evaluate :: e -> PolicyInput -> IO (Either EngineError EvaluationResult)

  -- | Get the engine type
  engineType :: e -> PolicyEngine

  -- | Add a policy to the engine
  addPolicy :: e -> Policy -> IO (Either EngineError ())

  -- | Remove all policies and reload
  clearPolicies :: e -> IO ()

  -- | Get information about loaded policies
  getPolicyInfo :: e -> IO [(Text, Text)]
    -- ^ Returns list of (policy ID, revision/hash)

-- | Detect the appropriate engine from a file path
detectEngine :: FilePath -> PolicyEngine
detectEngine path
  | ".cedar" `T.isSuffixOf` T.pack path = CedarEngine
  | ".rego" `T.isSuffixOf` T.pack path = RegoEngine
  | otherwise = AutoEngine

-- | Create an engine instance based on configuration
createEngine :: PolicyEngine -> IO (Either EngineError SomeEngine)
createEngine CedarEngine = do
  engine <- Cedar.newCedarEngine
  return $ Right $ SomeEngine engine
createEngine RegoEngine = do
  engine <- Rego.newRegoEngine
  return $ Right $ SomeEngine engine
createEngine AutoEngine = do
  -- Default to Cedar
  createEngine CedarEngine

-- | Existential wrapper for any engine
data SomeEngine = forall e. Engine e => SomeEngine e

instance Engine SomeEngine where
  evaluate (SomeEngine e) = evaluate e
  engineType (SomeEngine e) = engineType e
  addPolicy (SomeEngine e) = addPolicy e
  clearPolicies (SomeEngine e) = clearPolicies e
  getPolicyInfo (SomeEngine e) = getPolicyInfo e

-- | Load policies from configuration
loadPolicies :: Engine e => e -> [PolicyConfig] -> IO [Either EngineError ()]
loadPolicies engine configs = mapM (loadPolicyConfig engine) configs

-- | Load a single policy from configuration
loadPolicyConfig :: Engine e => e -> PolicyConfig -> IO (Either EngineError ())
loadPolicyConfig engine config = case pcType config of
  "file" -> case pcPath config of
    Just path -> do
      content <- readFile path
      let eng = detectEngine path
      addPolicy engine Policy
        { policyId = T.pack path
        , engine = eng
        , content = T.pack content
        , source = FileSource path
        }
    Nothing -> return $ Left $ LoadError "File policy missing 'path'"

  "inline" -> case pcContent config of
    Just content -> addPolicy engine Policy
      { policyId = "inline"
      , engine = AutoEngine
      , content = content
      , source = InlineSource content
      }
    Nothing -> return $ Left $ LoadError "Inline policy missing 'content'"

  "bundle" -> case pcUrl config of
    Just _url -> do
      -- Bundle loading requires an HTTP client (e.g., http-client-tls).
      -- Add http-client-tls to build-depends and implement HTTP GET + JSON
      -- decoding of the PolicyBundle type from Types.hs.
      return $ Left $ LoadError
        "Bundle loading requires http-client-tls dependency. Use 'file' or 'inline' policy types, or fetch bundles externally and provide them as files."
    Nothing -> return $ Left $ LoadError "Bundle policy missing 'url'"

  other -> return $ Left $ LoadError $ "Unknown policy type: " <> other

-- | Reload all policies from configuration
reloadPolicies :: Engine e => e -> [PolicyConfig] -> IO [Either EngineError ()]
reloadPolicies engine configs = do
  clearPolicies engine
  loadPolicies engine configs

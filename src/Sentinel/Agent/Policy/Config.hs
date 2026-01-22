-- |
-- Module      : Sentinel.Agent.Policy.Config
-- Description : Configuration types and loading
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Configuration types and YAML loading for the policy agent.

module Sentinel.Agent.Policy.Config
  ( -- * Configuration Types
    AgentConfig(..)
  , CacheConfig(..)
  , AuditConfig(..)
  , PolicyConfig(..)

    -- * Loading
  , loadConfig
  , defaultConfig

    -- * CLI Options
  , CLIOptions(..)
  , parseCLIOptions
  ) where

import Data.Aeson (FromJSON(..), ToJSON(..), (.:), (.:?), (.!=), withObject)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Yaml (decodeFileThrow, ParseException)
import GHC.Generics (Generic)
import Options.Applicative
import Sentinel.Agent.Policy.Types

-- | Cache configuration
data CacheConfig = CacheConfig
  { enabled :: !Bool
  , ttlSeconds :: !Int
  , maxEntries :: !Int
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (ToJSON)

instance FromJSON CacheConfig where
  parseJSON = withObject "CacheConfig" $ \v -> CacheConfig
    <$> v .:? "enabled" .!= True
    <*> v .:? "ttl_seconds" .!= 60
    <*> v .:? "max_entries" .!= 10000

-- | Audit logging configuration
data AuditConfig = AuditConfig
  { auditEnabled :: !Bool
  , includeInput :: !Bool
  , includePolicies :: !Bool
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (ToJSON)

instance FromJSON AuditConfig where
  parseJSON = withObject "AuditConfig" $ \v -> AuditConfig
    <$> v .:? "enabled" .!= True
    <*> v .:? "include_input" .!= True
    <*> v .:? "include_policies" .!= False

-- | Policy source configuration from YAML
data PolicyConfig = PolicyConfig
  { pcType :: !Text
  , pcPath :: !(Maybe FilePath)
  , pcContent :: !(Maybe Text)
  , pcUrl :: !(Maybe Text)
  , pcRefreshInterval :: !(Maybe Int)
  }
  deriving stock (Eq, Show, Generic)

instance FromJSON PolicyConfig where
  parseJSON = withObject "PolicyConfig" $ \v -> PolicyConfig
    <$> v .: "type"
    <*> v .:? "path"
    <*> v .:? "content"
    <*> v .:? "url"
    <*> v .:? "refresh_interval"

instance ToJSON PolicyConfig where
  toJSON = undefined -- Not needed for config loading

-- | Complete agent configuration
data AgentConfig = AgentConfig
  { socketPath :: !FilePath
  , engine :: !PolicyEngine
  , policies :: ![PolicyConfig]
  , inputMapping :: !InputMapping
  , defaultDecision :: !Decision
  , cache :: !CacheConfig
  , audit :: !AuditConfig
  , logLevel :: !Text
  }
  deriving stock (Eq, Show, Generic)

instance FromJSON AgentConfig where
  parseJSON = withObject "AgentConfig" $ \v -> AgentConfig
    <$> v .:? "socket" .!= "/tmp/sentinel-policy.sock"
    <*> v .:? "engine" .!= AutoEngine
    <*> v .:? "policies" .!= []
    <*> v .:? "input_mapping" .!= defaultInputMapping
    <*> v .:? "default_decision" .!= Deny
    <*> v .:? "cache" .!= defaultCacheConfig
    <*> v .:? "audit" .!= defaultAuditConfig
    <*> v .:? "log_level" .!= "info"

-- | Default input mapping
defaultInputMapping :: InputMapping
defaultInputMapping = InputMapping
  { principalMapping = HeaderPrincipal "X-User-ID"
  , resourceMapping = PathResource "/api/{resource_type}/{resource_id}"
  , actionMapping = ActionMapping
      { getMapsTo = "read"
      , postMapsTo = "create"
      , putMapsTo = "update"
      , patchMapsTo = "update"
      , deleteMapsTo = "delete"
      , defaultAction = "access"
      }
  }

-- | Default cache configuration
defaultCacheConfig :: CacheConfig
defaultCacheConfig = CacheConfig
  { enabled = True
  , ttlSeconds = 60
  , maxEntries = 10000
  }

-- | Default audit configuration
defaultAuditConfig :: AuditConfig
defaultAuditConfig = AuditConfig
  { auditEnabled = True
  , includeInput = True
  , includePolicies = False
  }

-- | Default agent configuration
defaultConfig :: AgentConfig
defaultConfig = AgentConfig
  { socketPath = "/tmp/sentinel-policy.sock"
  , engine = AutoEngine
  , policies = []
  , inputMapping = defaultInputMapping
  , defaultDecision = Deny
  , cache = defaultCacheConfig
  , audit = defaultAuditConfig
  , logLevel = "info"
  }

-- | Load configuration from YAML file
loadConfig :: FilePath -> IO AgentConfig
loadConfig path = decodeFileThrow path

-- | CLI options
data CLIOptions = CLIOptions
  { cliSocket :: !(Maybe FilePath)
  , cliConfig :: !(Maybe FilePath)
  , cliEngine :: !(Maybe PolicyEngine)
  , cliPolicyDir :: !(Maybe FilePath)
  , cliLogLevel :: !(Maybe Text)
  }
  deriving stock (Eq, Show)

-- | Parse command line options
parseCLIOptions :: IO CLIOptions
parseCLIOptions = execParser opts
  where
    opts = info (cliOptionsParser <**> helper)
      ( fullDesc
     <> progDesc "Policy evaluation agent for Sentinel reverse proxy"
     <> header "sentinel-policy-agent - Rego/Cedar policy evaluator" )

cliOptionsParser :: Parser CLIOptions
cliOptionsParser = CLIOptions
  <$> optional (strOption
      ( long "socket"
     <> short 's'
     <> metavar "PATH"
     <> help "Unix socket path" ))
  <*> optional (strOption
      ( long "config"
     <> short 'c'
     <> metavar "FILE"
     <> help "Configuration file path" ))
  <*> optional (option engineReader
      ( long "engine"
     <> short 'e'
     <> metavar "ENGINE"
     <> help "Policy engine (cedar, rego, auto)" ))
  <*> optional (strOption
      ( long "policy-dir"
     <> short 'p'
     <> metavar "DIR"
     <> help "Directory containing policy files" ))
  <*> optional (strOption
      ( long "log-level"
     <> short 'l'
     <> metavar "LEVEL"
     <> help "Log level (debug, info, warn, error)" ))

engineReader :: ReadM PolicyEngine
engineReader = eitherReader $ \s -> case T.toLower (T.pack s) of
  "cedar" -> Right CedarEngine
  "rego"  -> Right RegoEngine
  "opa"   -> Right RegoEngine
  "auto"  -> Right AutoEngine
  _       -> Left "Invalid engine: must be cedar, rego, or auto"

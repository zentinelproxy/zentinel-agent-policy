-- |
-- Module      : Sentinel.Agent.Policy
-- Description : Policy evaluation agent for Sentinel
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- This module provides a policy evaluation agent for the Sentinel
-- reverse proxy. It supports multiple policy languages:
--
-- * __Cedar__ - AWS's policy language for fine-grained access control
-- * __Rego__ - Open Policy Agent's declarative policy language
--
-- = Quick Start
--
-- @
-- import Sentinel.Agent.Policy
--
-- main :: IO ()
-- main = do
--   config <- loadConfig "policy.yaml"
--   runPolicyAgent config
-- @
--
-- = Configuration
--
-- The agent is configured via YAML:
--
-- @
-- engine: cedar  # or \"rego\" or \"auto\"
-- policies:
--   - type: file
--     path: /etc/sentinel/policies/authz.cedar
-- default_decision: deny
-- cache:
--   enabled: true
--   ttl_seconds: 60
-- @

module Sentinel.Agent.Policy
  ( -- * Running the Agent
    runPolicyAgent
  , newPolicyAgent

    -- * Configuration
  , AgentConfig(..)
  , CacheConfig(..)
  , AuditConfig(..)
  , loadConfig
  , defaultConfig
  , parseCLIOptions
  , CLIOptions(..)

    -- * Types
  , Decision(..)
  , PolicyInput(..)
  , Principal(..)
  , Resource(..)
  , Action(..)
  , EvaluationResult(..)
  , PolicyEngine(..)

    -- * Policy Engines
  , Engine(..)
  , CedarEngine
  , RegoEngine
  , newCedarEngine
  , newRegoEngine

    -- * Caching
  , DecisionCache
  , CacheStats(..)

    -- * Re-exports
  , module Sentinel.Agent.Policy.Types
  ) where

import Sentinel.Agent.Policy.Cache (DecisionCache, CacheStats(..))
import Sentinel.Agent.Policy.Cedar (CedarEngine, newCedarEngine)
import Sentinel.Agent.Policy.Config
import Sentinel.Agent.Policy.Engine (Engine(..))
import Sentinel.Agent.Policy.Handler (PolicyAgent, newPolicyAgent, runPolicyAgent)
import Sentinel.Agent.Policy.Rego (RegoEngine, newRegoEngine)
import Sentinel.Agent.Policy.Types

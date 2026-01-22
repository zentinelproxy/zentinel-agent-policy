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
--
-- = Requirements
--
-- This agent requires external CLI tools for policy evaluation:
--
-- * For Cedar policies: @cedar@ CLI (<https://github.com/cedar-policy/cedar>)
-- * For Rego policies: @opa@ CLI (<https://www.openpolicyagent.org/docs/latest/#running-opa>)

module Sentinel.Agent.Policy
  ( -- * Running the Agent
    runPolicyAgent
  , newPolicyAgent
  , PolicyAgent

    -- * Configuration
  , AgentConfig(..)
  , CacheConfig(..)
  , AuditConfig(..)
  , PolicyConfig(..)
  , loadConfig
  , defaultConfig
  , parseCLIOptions
  , CLIOptions(..)

    -- * Types
  , Decision(..)
  , DecisionReason(..)
  , PolicyInput(..)
  , Principal(Principal, principalId, principalType)
  , Resource(Resource, resourceId, resourceType, path)
  , Action(Action, actionName, method)
  , EvaluationResult(..)
  , PolicyEngine(..)
  , PolicySource(..)
  , Policy(Policy, policyId, content, source)

    -- * Input Mapping
  , InputMapping(..)
  , PrincipalMapping(..)
  , ResourceMapping(..)
  , ActionMapping(..)

    -- * Policy Engines
  , Engine(..)
  , EngineError(..)
  , CedarEngine
  , RegoEngine
  , newCedarEngine
  , newRegoEngine

    -- * Caching
  , DecisionCache
  , CacheStats(..)
  , newCache
  ) where

import Sentinel.Agent.Policy.Cache (DecisionCache, CacheStats(..), newCache)
import Sentinel.Agent.Policy.Cedar (CedarEngine, newCedarEngine)
import Sentinel.Agent.Policy.Config
import Sentinel.Agent.Policy.Engine (Engine(..), EngineError(..))
import Sentinel.Agent.Policy.Handler (PolicyAgent, newPolicyAgent, runPolicyAgent)
import Sentinel.Agent.Policy.Rego (RegoEngine, newRegoEngine)
import Sentinel.Agent.Policy.Types

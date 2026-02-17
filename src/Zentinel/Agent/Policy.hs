-- |
-- Module      : Zentinel.Agent.Policy
-- Description : Policy evaluation agent for Zentinel
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- This module provides a policy evaluation agent for the Zentinel
-- reverse proxy. It supports multiple policy languages:
--
-- * __Cedar__ - AWS's policy language for fine-grained access control
-- * __Rego__ - Open Policy Agent's declarative policy language
--
-- = Quick Start
--
-- @
-- import Zentinel.Agent.Policy
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
--     path: /etc/zentinel/policies/authz.cedar
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

module Zentinel.Agent.Policy
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

import Zentinel.Agent.Policy.Cache (DecisionCache, CacheStats(..), newCache)
import Zentinel.Agent.Policy.Cedar (CedarEngine, newCedarEngine)
import Zentinel.Agent.Policy.Config
import Zentinel.Agent.Policy.Engine (Engine(..), EngineError(..))
import Zentinel.Agent.Policy.Handler (PolicyAgent, newPolicyAgent, runPolicyAgent)
import Zentinel.Agent.Policy.Rego (RegoEngine, newRegoEngine)
import Zentinel.Agent.Policy.Types

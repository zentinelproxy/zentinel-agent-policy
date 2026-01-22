{-# LANGUAGE DuplicateRecordFields #-}
-- |
-- Module      : Sentinel.Agent.Policy.Types
-- Description : Core types for policy evaluation
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Core types used throughout the policy agent including decisions,
-- policy sources, and evaluation contexts.

module Sentinel.Agent.Policy.Types
  ( -- * Decision Types
    Decision(..)
  , DecisionReason(..)
  , EvaluationResult(..)

    -- * Policy Types
  , PolicyEngine(..)
  , PolicySource(..)
  , PolicyBundle(..)
  , Policy(..)

    -- * Input Types
  , PolicyInput(..)
  , Principal(..)
  , Resource(..)
  , Action(..)

    -- * Mapping Types
  , InputMapping(..)
  , PrincipalMapping(..)
  , ResourceMapping(..)
  , ActionMapping(..)

    -- * Audit Types
  , AuditEntry(..)
  ) where

import Data.Aeson (FromJSON, ToJSON, Value)
import Data.Hashable (Hashable)
import Data.Map.Strict (Map)
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)

-- | The result of a policy evaluation
data Decision
  = Allow
  | Deny
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON, Hashable)

-- | Reason for a policy decision
data DecisionReason = DecisionReason
  { matchedPolicies :: ![Text]
    -- ^ Names/IDs of policies that contributed to the decision
  , message :: !(Maybe Text)
    -- ^ Human-readable explanation
  , details :: !(Maybe Value)
    -- ^ Additional structured details from the policy engine
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | Complete result of policy evaluation
data EvaluationResult = EvaluationResult
  { decision :: !Decision
  , reason :: !DecisionReason
  , evaluationTimeNs :: !Integer
    -- ^ Time taken for evaluation in nanoseconds
  , cached :: !Bool
    -- ^ Whether this result came from cache
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | Supported policy engines
data PolicyEngine
  = CedarEngine
  | RegoEngine
  | AutoEngine
    -- ^ Automatically detect engine from policy file extension
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | Source of a policy
data PolicySource
  = FileSource !FilePath
    -- ^ Load policy from file
  | InlineSource !Text
    -- ^ Inline policy content
  | BundleSource !Text !Int
    -- ^ Remote bundle URL and refresh interval in seconds
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | A bundle of policies from a remote source
data PolicyBundle = PolicyBundle
  { bundleId :: !Text
  , revision :: !Text
  , policies :: ![Policy]
  , fetchedAt :: !UTCTime
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | A single policy definition
data Policy = Policy
  { policyId :: !Text
  , engine :: !PolicyEngine
  , content :: !Text
  , source :: !PolicySource
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | Input context for policy evaluation
data PolicyInput = PolicyInput
  { principal :: !Principal
  , action :: !Action
  , resource :: !Resource
  , context :: !(Map Text Value)
    -- ^ Additional context data (headers, query params, etc.)
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON, Hashable)

-- | The principal (actor) making the request
data Principal = Principal
  { principalId :: !Text
  , principalType :: !(Maybe Text)
  , attributes :: !(Map Text Value)
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON, Hashable)

-- | The resource being accessed
data Resource = Resource
  { resourceId :: !Text
  , resourceType :: !(Maybe Text)
  , path :: !Text
  , attributes :: !(Map Text Value)
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON, Hashable)

-- | The action being performed
data Action = Action
  { actionName :: !Text
  , method :: !Text
    -- ^ HTTP method
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON, Hashable)

-- | Configuration for how to extract principal from request
data PrincipalMapping
  = HeaderPrincipal !Text
    -- ^ Extract principal from header
  | JWTClaimPrincipal !Text
    -- ^ Extract from JWT claim (assumes JWT is already validated)
  | QueryParamPrincipal !Text
    -- ^ Extract from query parameter (for testing)
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | Configuration for how to extract resource from request
data ResourceMapping
  = PathResource !Text
    -- ^ Extract from path pattern
  | HeaderResource !Text
    -- ^ Extract from header
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | Configuration for how to map HTTP methods to actions
data ActionMapping = ActionMapping
  { getMapsTo :: !Text
  , postMapsTo :: !Text
  , putMapsTo :: !Text
  , patchMapsTo :: !Text
  , deleteMapsTo :: !Text
  , defaultAction :: !Text
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | Complete input mapping configuration
data InputMapping = InputMapping
  { principalMapping :: !PrincipalMapping
  , resourceMapping :: !ResourceMapping
  , actionMapping :: !ActionMapping
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | Audit log entry for a policy decision
data AuditEntry = AuditEntry
  { timestamp :: !UTCTime
  , requestId :: !Text
  , input :: !PolicyInput
  , result :: !EvaluationResult
  , policyVersion :: !Text
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

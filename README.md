# sentinel-agent-policy

Policy evaluation agent for [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy. Supports multiple policy languages including [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) (OPA) and [Cedar](https://www.cedarpolicy.com/).

[![Hackage](https://img.shields.io/hackage/v/sentinel-agent-policy.svg)](https://hackage.haskell.org/package/sentinel-agent-policy)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Features

- **Multi-Engine Support** - Rego (OPA) and Cedar policy languages
- **Request Context Evaluation** - Full access to request metadata, headers, path, method
- **Flexible Policy Loading** - File-based, inline, or remote policy bundles
- **Hot Reload** - Update policies without restarting the agent
- **Audit Logging** - Detailed decision audit trail with matched rules
- **Caching** - Optional decision caching for performance
- **Pure Haskell** - No external runtime dependencies for Cedar; OPA via embedded engine

## Installation

### From Hackage

```bash
cabal install sentinel-agent-policy
```

### From source

```bash
git clone https://github.com/raskell-io/sentinel-agent-policy
cd sentinel-agent-policy
cabal build
```

## Usage

```bash
sentinel-policy-agent --socket /var/run/sentinel/policy.sock --config policy.yaml
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-policy.sock` |
| `--config` | `POLICY_CONFIG` | Configuration file path | - |
| `--engine` | `POLICY_ENGINE` | Policy engine (`cedar`, `rego`, `auto`) | `auto` |
| `--policy-dir` | `POLICY_DIR` | Directory containing policy files | - |
| `--log-level` | `LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) | `info` |

## Configuration

### Configuration File (YAML)

```yaml
# Policy engine configuration
engine: cedar  # or "rego" or "auto"

# Policy sources
policies:
  # File-based policies
  - type: file
    path: /etc/sentinel/policies/authz.cedar

  # Inline policy
  - type: inline
    content: |
      permit(
        principal,
        action == Action::"read",
        resource
      ) when {
        principal.role == "viewer"
      };

  # Remote bundle (OPA-style)
  - type: bundle
    url: https://policy-server.example.com/v1/policies
    refresh_interval: 60s

# Input mapping - how to build policy input from request
input_mapping:
  principal:
    type: header
    name: X-User-ID
  resource:
    type: path
    pattern: "/api/{resource_type}/{resource_id}"
  action:
    type: method_mapping
    GET: read
    POST: create
    PUT: update
    DELETE: delete

# Default decision when no policy matches
default_decision: deny

# Caching
cache:
  enabled: true
  ttl: 60s
  max_entries: 10000

# Audit logging
audit:
  enabled: true
  include_input: true
  include_policies: false
```

### Cedar Policy Example

```cedar
// Allow authenticated users to read public resources
permit(
  principal,
  action == Action::"read",
  resource
) when {
  resource.visibility == "public"
};

// Allow resource owners full access
permit(
  principal,
  action,
  resource
) when {
  principal == resource.owner
};

// Deny access to admin endpoints unless admin role
forbid(
  principal,
  action,
  resource
) when {
  resource.path.hasPrefix("/admin") &&
  principal.role != "admin"
};
```

### Rego Policy Example

```rego
package sentinel.authz

default allow := false

# Allow authenticated users to read public resources
allow {
  input.action == "read"
  input.resource.visibility == "public"
}

# Allow resource owners full access
allow {
  input.principal.id == input.resource.owner_id
}

# Deny access to admin endpoints unless admin role
deny {
  startswith(input.resource.path, "/admin")
  input.principal.role != "admin"
}

# Final decision
decision := "allow" {
  allow
  not deny
}

decision := "deny" {
  not allow
}

decision := "deny" {
  deny
}
```

### Sentinel Proxy Configuration

Add to your Sentinel `config.kdl`:

```kdl
agents {
    agent "policy" {
        type "custom"
        unix-socket path="/var/run/sentinel/policy.sock"
        events "request_headers"
        timeout-ms 100
        failure-mode "closed"  # Deny on policy engine failure
    }
}

routes {
    route "api" {
        matches { path-prefix "/api" }
        upstream "backend"
        agents ["policy"]
    }
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    sentinel-agent-policy                         │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Request Handler                         │  │
│  │  • Extract principal, action, resource from request        │  │
│  │  • Build policy input context                              │  │
│  └─────────────────────────┬─────────────────────────────────┘  │
│                            │                                     │
│  ┌─────────────────────────▼─────────────────────────────────┐  │
│  │                   Policy Evaluator                         │  │
│  │  ┌─────────────┐              ┌─────────────┐             │  │
│  │  │   Cedar     │              │    Rego     │             │  │
│  │  │  Evaluator  │              │  Evaluator  │             │  │
│  │  │  (native)   │              │  (via OPA)  │             │  │
│  │  └─────────────┘              └─────────────┘             │  │
│  └─────────────────────────┬─────────────────────────────────┘  │
│                            │                                     │
│  ┌─────────────────────────▼─────────────────────────────────┐  │
│  │                  Decision Cache                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │ Unix Socket (v2 Protocol)
                               ▼
                    ┌─────────────────────┐
                    │   Sentinel Proxy    │
                    └─────────────────────┘
```

## Metrics

The agent exposes Prometheus metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `policy_evaluations_total` | Counter | Total policy evaluations |
| `policy_decisions_total` | Counter | Decisions by result (allow/deny) |
| `policy_evaluation_duration_seconds` | Histogram | Evaluation latency |
| `policy_cache_hits_total` | Counter | Cache hits |
| `policy_cache_misses_total` | Counter | Cache misses |
| `policy_errors_total` | Counter | Policy evaluation errors |

## Development

### Prerequisites

- GHC 9.8+
- Cabal 3.10+

### Building

```bash
# Build
cabal build

# Run tests
cabal test

# Run with debug logging
cabal run sentinel-policy-agent -- --socket /tmp/policy.sock --log-level debug
```

### Project Structure

```
sentinel-agent-policy/
├── app/
│   └── Main.hs              # CLI entry point
├── src/
│   └── Sentinel/
│       └── Agent/
│           └── Policy/
│               ├── Config.hs      # Configuration types
│               ├── Engine.hs      # Policy engine interface
│               ├── Cedar.hs       # Cedar evaluator
│               ├── Rego.hs        # Rego/OPA evaluator
│               ├── Input.hs       # Input mapping
│               ├── Cache.hs       # Decision caching
│               └── Handler.hs     # Agent handler
├── test/
│   └── ...
├── policies/                 # Example policies
│   ├── example.cedar
│   └── example.rego
├── sentinel-agent-policy.cabal
├── cabal.project
└── README.md
```

## License

Apache-2.0

## Contributing

Contributions welcome! Please see the [Sentinel contributing guide](https://sentinel.raskell.io/docs/contributing).

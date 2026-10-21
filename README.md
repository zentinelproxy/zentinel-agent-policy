<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Policy agent</h3>

<p align="center">An experimental Haskell agent that decides requests with Cedar or Rego (OPA) policies on request headers. Not yet usable with Zentinel.</p>

<p align="center">
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/policy/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

The agent maps each request to a principal (a header), an action (the HTTP
method) and a resource (the path), evaluates that input against
[Cedar](https://www.cedarpolicy.com/) or
[Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies
by calling the `cedar` or `opa` command-line tool, and allows the request or
answers `403`. Decisions are cached.

## Status

**Experimental. It does not work with the Zentinel proxy today.**

- The agent implements its own socket framing (a 4-byte length followed by
  JSON with `type`/`data` fields). Agent protocol v2 over a Unix socket uses a
  4-byte length, a 1-byte message type and then the payload, so the proxy and
  this agent cannot complete a handshake.
- There is no release. `zentinel bundle list` shows `policy 0.1.0`, but no
  release assets exist, so `zentinel bundle install policy` cannot download it.
  The package is not on Hackage.
- There is no CI workflow; the code has not been built or tested here for this
  README.

## Install

From source only. The toolchain is pinned in `mise.toml` (GHC 9.8, Cabal 3.10).

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-policy
cd zentinel-agent-policy
mise install
cabal build
cabal install exe:zentinel-policy-agent
```

Evaluation needs the policy engine's CLI on `PATH`:

- Cedar: the [cedar CLI](https://github.com/cedar-policy/cedar) (`cargo install cedar-policy-cli`)
- Rego: the [opa CLI](https://www.openpolicyagent.org/docs/latest/#running-opa)

## Configuration

```bash
zentinel-policy-agent --socket /var/run/zentinel/policy.sock --config policy.yaml
```

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `-s`, `--socket` | `AGENT_SOCKET` | `/tmp/zentinel-policy.sock` | Unix socket to listen on |
| `-c`, `--config` | `POLICY_CONFIG` | none | YAML configuration file |
| `-e`, `--engine` | `POLICY_ENGINE` | `auto` | `cedar`, `rego` (or `opa`), `auto` |
| `-l`, `--log-level` | `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `-p`, `--policy-dir` | none | none | Parsed but not used |

The YAML file has the top-level keys `socket`, `engine`, `policies`,
`input_mapping`, `default_decision`, `cache` (`enabled`, `ttl_seconds`,
`max_entries`), `audit` (`enabled`, `include_input`, `include_policies`) and
`log_level`. Each entry of `policies` has a `type` of `file` (with `path`; the
engine is chosen from the `.cedar` or `.rego` extension) or `inline` (with
`content`). `bundle` is accepted by the parser but loading a remote bundle is
not implemented.

`engine`, `default_decision` and `input_mapping` are decoded with generic
instances, so they take the Haskell constructor names (`CedarEngine`,
`RegoEngine`, `AutoEngine`; `Allow`, `Deny`), not the lowercase words. Without
an `input_mapping` the principal comes from `X-User-ID`, the resource from the
path pattern `/api/{resource_type}/{resource_id}`, and the action from the
method (`GET` read, `POST` create, `PUT`/`PATCH` update, `DELETE` delete,
otherwise access). Without `default_decision` an evaluation error denies.

Example policies are in [`policies/`](policies/).

## Development

```bash
mise install
cabal build
cabal test
```

## Related

- [Registry page](https://registry.zentinelproxy.io/policy/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [zentinel-agent-haskell-sdk](https://github.com/zentinelproxy/zentinel-agent-haskell-sdk)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>

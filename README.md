# Sosya

**Describe a hacking lab in plain English. Get it running, isolated and verified.**

> Status: pre-release. Sosya v0.1 ships on November 24, 2026.

Sosya turns one sentence into a working, multi-container security lab. It builds it from real,
documented vulnerable environments ([Vulhub](https://github.com/vulhub/vulhub)), checks that it
actually works, and keeps it isolated from your network by default.

```console
$ sosya new "Struts2 app in a DMZ, passwordless Redis reachable only from the web server"
$ sosya shell dmz-redis    # Kali, inside the range network
```

## Why Sosya

- **Verified.** A range is "ready" only after it boots and every service answers from the
  attacker box.
- **Safe by default.** No ports published on your host: targets live on internal networks.
- **Lightweight.** Docker on a laptop. No hypervisor, no dedicated server.
- **Any LLM.** Anthropic, OpenAI or any OpenAI-compatible endpoint, including local models via
  Ollama.

## Try what exists today

From a checkout of this repository, with [uv](https://docs.astral.sh/uv/) installed:

```console
uv run sosya doctor
```

Ranges from the gallery ship inside the package, so they start right after installation, with no
repository and no LLM key:

```console
$ sosya up dmz-redis       # Struts2 in a DMZ, Redis only on the internal network
$ sosya shell dmz-redis
$ sosya down dmz-redis
```

## For AI agents: `sosya mcp`

`sosya mcp` is an MCP server on stdio. It works with any MCP client:

```json
{
  "mcpServers": {
    "sosya": { "command": "sosya", "args": ["mcp"] }
  }
}
```

An agent can act as the planner itself, with no LLM key: `catalog_search`, write a
`range.yaml`, `check_range` until it has no errors, then `up`, `validate`, `scenario` and `down`.
`new` (one sentence to a green range) appears only when an LLM provider is configured.
`attacker_exec` runs commands in the attacker box only for ranges with `attacker.internet: false`,
and `check_flag` checks a captured flag without revealing it. Environments with host-level
privileges are always refused over MCP.

The server keeps its ranges in `$XDG_STATE_HOME/sosya` (`~/.local/state/sosya`), or in
`--workspace` / `SOSYA_WORKSPACE`; `sosya status` and `sosya down` see them from anywhere.

## Responsible use

Sosya builds local labs for training and research on systems you own. It does not generate or run
exploits.

## Credits

Vulnerable environments by [Vulhub](https://github.com/vulhub/vulhub), MIT license.

## License

[MIT](LICENSE)

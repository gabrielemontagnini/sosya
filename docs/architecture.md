# Architecture

This document records design decisions that the code must follow. Each decision lists the
evidence behind it.

## Network isolation model

Decided on 2026-11-20 from a spike run on Docker Engine 29.10.0 and Docker Compose v5.8.0
(Linux, x86_64).

### Rules for the renderer

1. **One Docker network per scenario segment** (`dmz`, `internal`, ...). Each one is a bridge
   with `internal: true`, `enable_ipv6: false` and the driver option
   `com.docker.network.bridge.gateway_mode_ipv4: isolated`.
2. **No `ports:` on target services.** The renderer strips every `ports` entry it copies from Vulhub.
3. **The attacker box is the only container with internet access.** When `attacker.internet` is
   true, it also joins a separate network named `egress`, a plain bridge that is not internal.
   No target ever joins `egress`.
4. **The attacker box does not forward packets (defense in depth).** The renderer always sets
   `sysctls: {net.ipv4.ip_forward: "0"}` on it. Without it, the spike measured `ip_forward` at
   `1` inside the attacker box. This is not an exploitable path in the default setup: to route
   through the attacker box, a target would need to change its own routing table, which requires
   `CAP_NET_ADMIN`, and Docker does not grant that capability by default. The sysctl is an extra
   layer, so that egress stays closed even if a target is ever started with more capabilities.
5. **Pivoting comes from dual-homed hosts only.** A host on two segments, such as `web` on
   `dmz` and `internal`, is the only path between them. The attacker box joins only the
   segments listed in `attacker.networks`.
6. **`--expose` and `--proxy` publish on `127.0.0.1` only**, through a separate network that is
   not internal (the same pattern as `egress`). An address that is empty or `0.0.0.0` is a bug.
7. **Networks are IPv4 only.** Segment networks set `enable_ipv6: false` explicitly, instead
   of relying on the daemon default. If IPv6 is ever enabled, set `gateway_mode_ipv6: isolated`
   too.
8. **Dangerous services need explicit consent.** See
   [Services with host-level privileges](#services-with-host-level-privileges).

Example of a rendered segment network:

```yaml
networks:
  dmz:
    internal: true
    enable_ipv6: false
    driver_opts:
      com.docker.network.bridge.gateway_mode_ipv4: isolated
```

### Minimum Docker version: Engine 28.0.0

The `isolated` gateway mode arrived in Docker Engine 28.0.0 (released 2025-02-19). The
[official Docker Engine 28 release notes](https://docs.docker.com/engine/release-notes/28/),
section 28.0.0, "Networking", "Port publishing in bridge networks", say:

> Bridge driver options `com.docker.network.bridge.gateway_mode_ipv4` and
> `com.docker.network.bridge.gateway_mode_ipv6` now accept mode `isolated`, when the network is
> also `internal`.
>
> An `internal` bridge network created with gateway mode `isolated` does not have an address on
> the Docker host.

The change is [moby/moby#49262](https://github.com/moby/moby/pull/49262). The mode is valid only
on internal networks.

Sosya does not rely on how older engines react to the option:

- `sosya doctor` fails (not just warns) when the Docker Engine is older than 28.0.0.
- `sosya up` runs the same version check before rendering and refuses to start.

### Why `internal: true` alone is not enough

On Linux, an ordinary internal bridge still gets a gateway address on the host. The host, and
any process on it, can then connect straight to container IPs, even with no ports published.
The spike measured exactly that:

| Check | `internal: true` only | `internal: true` + `gateway_mode_ipv4: isolated` |
| --- | --- | --- |
| Host → `web` container IP `:8080` (both segments) | **reachable** | refused |
| Host → `cache` container IP `:6379` | **reachable** | refused |

With `isolated`, the bridge has no host address. Containers get the subnet's `.1` address, which
otherwise belongs to the gateway, and the host has no route into the segment.

### Spike results (isolated model, 30/30 checks passed)

Topology: `web` = `vulhub/struts2:2.3.30` on `dmz` and `internal`; `cache` =
`vulhub/redis:4.0.14` on `internal`; `attacker` = `alpine:3.20` on `dmz` and `egress`. Probes
from the targets ran in their network namespace (`docker run --network container:<id>`), so
the results do not depend on which tools the target images include. Every network check was run
twice, once by DNS name and once by container IP.

| # | Check | Result |
| --- | --- | --- |
| 1 | No published ports on targets; no host listener on 8080/6379 | pass |
| 1 | Host → target container IPs (every segment) | refused |
| 2 | Attacker → `web:8080`, by name and by IP | HTTP 200 |
| 2 | Pivot: `web` → `cache:6379`, by name and by IP | `PONG` |
| 2 | Segmentation: attacker → `cache` by name, by IP, and → `web`'s `internal` IP | refused / unresolved |
| 2 | Attacker `net.ipv4.ip_forward` | `0` (set explicitly) |
| 3 | Targets: DNS, TCP to `1.1.1.1:443`, TCP to `[2606:4700::1111]:443`, HTTP, default route | all absent or failed |
| 4 | Attacker: `apk add`, DNS, HTTPS, TCP to `1.1.1.1:443` | ok |
| 5 | `ports: ["127.0.0.1:18080:80"]` on a separate network that is not internal | answers on `127.0.0.1`, refused on the host's LAN IP |

## Services with host-level privileges

The catalog builder marks an environment as **dangerous** when any of its services uses one of:

- `privileged: true`
- `cap_add`, `devices` or `security_opt`
- `network_mode`, unless it is `service:<name>` towards a service of the same component
- `pid: host`, `ipc: host` or `userns_mode: host`
- a bind mount whose source is absolute (including `docker.sock`) or leaves the component
  directory

The builder and the renderer share these rules (`sosya.catalog.rules`), so a key can never look
harmless to one and pass the other.

### Allowlist of compose keys

The renderer copies a Vulhub service key by key and accepts only keys listed in
`sosya.catalog.rules`. Everything else makes both the catalog build and the renderer fail with
the environment id, so a new Vulhub pin cannot bring in an unreviewed key. The list comes from an
inventory of the 334 compose files at the pinned commit (2026-11-21):

- Copied: `image`, `build`, `command`, `entrypoint`, `environment`, `env_file`, `depends_on`
  (renamed), `healthcheck`, `user`, `restart` (`always` and `unless-stopped` become
  `on-failure`, so a target never comes back by itself after a daemon restart), `hostname`,
  `working_dir`, `init`, `tty`, `shm_size`, `ulimits`, `labels` (`sosya.*` and `com.docker.*`
  refused), `volumes` (binds and anonymous volumes only), `expose`.
- Consumed: `ports` and `container_name` are removed; `links` become network aliases;
  `networks` are replaced by the range's own.
- Host-level keys (the list above): only in dangerous environments, with consent.
- Every bind source in the catalog is a relative path inside the component directory: no
  absolute bind, not even `/etc/localtime`, had to be allowed.
- Interpolation: the rendered file must not depend on the environment of whoever runs
  `sosya up`. `${VAR:-default}` and `${VAR-default}` become their default; `$$` is kept. Any
  other form is refused. The catalog uses only these two forms (airflow, chartbrew,
  jumpserver, neo4j, rocketchat).

At the pinned Vulhub commit, 2 of the 334 environments are marked, both for `privileged: true`:

- `ingress-nginx/CVE-2025-1974`
- `docker/unauthorized-rce`

Rules:

- The planner never picks a dangerous environment by itself: these environments are left out of
  its candidate list unless the user's prompt names them.
- `sosya up` starts a range that contains a dangerous environment only with `--allow-privileged`
  and an explicit interactive confirmation, which lists each flagged service and the reason it was
  flagged. Without the flag it refuses to start.
- When a plan contains a dangerous environment, the plan preview flags it prominently, with a
  clear warning mark and the reasons, next to the affected host. It is never hidden in the
  details.
- `sosya new` follows the same rule as `sosya up`: it builds a plan that contains a dangerous
  environment only with `--allow-privileged` and an explicit interactive confirmation. Without
  the flag it shows the plan with the warning and stops before building.
- The MCP server always rejects dangerous environments, even when the agent asks for them by
  name or passes a `range.yaml` it wrote itself. The rejection explains that these environments
  can only be started from the CLI, with `--allow-privileged` and a person confirming. No MCP
  argument overrides this.

## Image architectures

Checked on 2026-11-20 with `docker buildx imagetools inspect` and cross-checked with
`docker manifest inspect -v`. Images are those of the gallery candidates at the pinned Vulhub
commit `9b90d4276f84feed6333286afeb7e1250379a1da`.

| Image | Used by | Platforms |
| --- | --- | --- |
| `vulhub/struts2:2.3.30` | struts2/s2-045 | linux/amd64 only |
| `vulhub/redis:4.0.14` | redis/4-unacc | linux/amd64 only |
| `vulhub/wordpress:4.6` | wordpress/pwnscriptum | linux/amd64 only |
| `mysql:5` | wordpress/pwnscriptum | linux/amd64 only |
| `vulhub/solr:8.11.0` | log4j/CVE-2021-44228 | linux/amd64 only |
| `vulhub/grafana:8.2.6` | grafana/CVE-2021-43798 | linux/amd64 only |
| `vulhub/drupal:8.5.0` | drupal/CVE-2018-7600 | linux/amd64 only |
| `vulhub/samba:4.6.3` | samba/CVE-2017-7494 | linux/amd64 only |
| `vulhub/openssh:7.7` | openssh/CVE-2018-15473 (base of its `build:`) | linux/amd64 only |
| `vulhub/jenkins:2.138` | jenkins/CVE-2018-1000861 | linux/amd64 only |
| `kalilinux/kali-rolling` | attacker box | linux/386, amd64, arm/v7, arm64 |
| `alpine:3.20` | spike attacker box | multi-arch, arm64 included |

Consequences:

- Every gallery target is amd64 only. On arm64 hosts, these images run only under emulation
  (QEMU/binfmt or Rosetta), which is slow and sometimes broken. `sosya doctor` keeps warning on
  ARM hosts.
- The renderer sets `platform:` on every Vulhub service: the engine's own platform when the
  image has it, otherwise `linux/amd64`. An ARM host with emulation then pulls the right image
  and gets a clear error otherwise, instead of a silent `no matching manifest`, and the one
  arm64-only environment (`python/CVE-2024-23334`) still runs natively on ARM. The attacker box
  keeps the native platform.
- The host platform is read from the Docker daemon (`docker info`, `OSType/Architecture`), not
  from Python: `platform.machine()` is wrong for an x86_64 Python under Rosetta and for a remote
  Docker context. `sosya catalog` falls back to it only when the daemon does not answer.
- `spec.check_catalog` fails a range whose images cannot run on the engine's platform, and
  warns when they run only under emulation (amd64 images on an arm64 engine).
- `openssh/CVE-2018-15473` uses `build:`, so it is not in the image-only set. Its base image is
  amd64 only as well.

### Platforms in the catalog index

The catalog index stores the platforms of every image it references, for example
`"platforms": ["linux/amd64"]`. For a `build:` service, it stores the platforms of the final
`FROM` image. With this data, `sosya doctor` and the planner can warn for each range, before
anything is pulled, when the host's architecture is not among an image's platforms.

Detection is a separate, resumable development step (`python -m sosya.catalog.build platforms`)
with a committed cache in `data/vulhub-platforms.json`, written after every image:

1. **Docker Hub images: the Docker Hub web API**,
   `hub.docker.com/v2/repositories/<namespace>/<repo>/tags/<tag>`, field `images` (`os`,
   `architecture`, `variant`; `unknown/unknown` attestation entries are ignored). This API does
   not touch the registry, so it does not use up the registry pull limit that `sosya up` needs.
   Measured on 2026-11-21: the anonymous registry counter (`ratelimit-remaining` on a `HEAD` of
   `ratelimitpreview/test`, which does not count as a pull) read `100;w=3600` before and after a
   full run of 346 API lookups. The web API has its own limit (`x-ratelimit-limit: 180`); on a
   short `429` the builder waits for `x-ratelimit-reset`, on a long one it saves and stops.
2. **Fallback: `docker buildx imagetools inspect`**, for other registries and for Docker Hub
   images when the web API does not answer. It reads the manifest list's `platform` entries, or
   the image config's `os`/`architecture` for a single manifest. On Docker Hub this reads
   manifests from the registry and counts against the pull limit, so it runs only when
   `docker login` has stored Docker Hub credentials.

Results at the pinned commit (347 distinct images: 346 from the web API, 1 from `gcr.io` via
`imagetools`):

| Environments | Platforms |
| --- | --- |
| 326 | `linux/amd64` only |
| 5 | `linux/amd64` and `linux/arm64` |
| 1, `python/CVE-2024-23334` | `linux/arm64` only: `vulhub/aiohttp:3.9.1` is a single arm64 manifest |
| 2, `craftcms/CVE-2025-32432`, `budibase/CVE-2026-31816` | unknown: `vulhub/craftcms:5.6.16` does not exist (registry `404`); the pinned `minio/minio` tag is no longer public (`401`) |

The three environments in the last two rows do not start on an amd64 host as they are.

## Where `sosya up` finds a range

`sosya up <target>` looks, in this order, for:

1. a path to a `range.yaml` or to its directory;
2. a range name recorded in `.sosya/state.json` whose source still exists;
3. `ranges/<name>/range.yaml` in the current directory;
4. the gallery shipped inside the package, `sosya/gallery/<name>/range.yaml`.

The gallery is part of the wheel, so `uv tool install sosya && sosya up dmz-redis` works from
any directory with no repository and no LLM key. CI checks that the gallery is in the wheel
and the sdist, and that every gallery range passes `load_range` and `check_catalog` from the
installed wheel.

## LLM adapters

Two adapters, both plain HTTP with `httpx` and no vendor SDK, behind one interface: complete a
conversation into JSON for a JSON Schema (`sosya.llm.base.LLM.complete_json`).

- **Anthropic**: `POST /v1/messages` with `output_config.format` (`json_schema`). Requests never
  set `temperature`, `top_p`, `top_k`, `thinking` or an assistant prefill, which current models
  reject. Forced tool use is not used: recent models reject `tool_choice` `tool`/`any`.
- **OpenAI-compatible** (OpenAI, Ollama, LM Studio, vLLM, OpenRouter): `POST /chat/completions`
  with `response_format` `json_schema` and `strict: true`. If the server rejects it with a 400
  or 422 about the response format, the adapter switches to text mode for the rest of the
  process: the schema goes into the system prompt and the JSON is read from the reply.
- **Schemas** are stable and dedicated (`sosya.llm.schema.strict_schema`): every object closed
  with `additionalProperties: false`, every property required, unsupported constraints
  (lengths, bounds, patterns, defaults) removed and checked again by Pydantic. A schema never
  depends on the request, because every change recompiles the provider's grammar.
- **Stops**: `refusal` raises `RefusalError` (with its category); `max_tokens` or `length`
  retries with twice the output tokens, up to 64000, leaving room for adaptive reasoning.
- **Retries**: connection errors and 408, 409, 429, 5xx and 529, at most 4 attempts, honouring
  `retry-after`. Errors carry the status and the server's error type and message, with any
  key scrubbed.
- **Model**: `--model`, else `SOSYA_MODEL`. Otherwise the Anthropic adapter lists
  `GET /v1/models` and takes the newest model of the sonnet line by `created_at` (cached for
  24 hours in `~/.cache/sosya/models.json`). The OpenAI-compatible adapter takes the only model
  the endpoint lists and stops with the list when there are several.
- No model id appears in code, tests, docs or prompts; tests use fake ids.

## Implications for `render/` and `runtime/`

- `render/`: apply rules 1-8 above. Every segment network gets `internal: true`,
  `enable_ipv6: false` and the `isolated` gateway option. `egress` exists only when
  `attacker.internet` is true. The attacker box gets the `ip_forward` sysctl. Vulhub services
  get `platform:` as described in [Image architectures](#image-architectures). Snapshot
  tests assert that the rendered output contains no `ports` outside the `127.0.0.1` networks.
- Names: in a host, the main service takes the host's name (the service named by `service:`,
  else the first one with `ports`); the others become `<host>-<service>`. Every service that
  Vulhub publishes with `ports` joins the host's segment networks; services without ports stay
  private. A component with two or more services gets a private network `<host>-net`, with the
  original service names (and `links` aliases) as network aliases, so `DB_HOST=mysql` keeps
  working; a single-service component needs none, which saves networks from Docker's address
  pools. Clashing generated names, and DNS names that would mean two containers to the same
  container, are errors in both `check_catalog` and the renderer.
- Bind mounts: each range works on its own copy of the component's files, in
  `.sosya/ranges/<name>/files/<host>/`, because targets are compromised by design. The shared
  Vulhub cache is only the source for `build` contexts and `env_file`. `sosya down` deletes the
  copy, with a throwaway container when a target left files owned by root.
- `runtime/`: check the Docker Engine version (at least 28.0.0) before `up`, and enforce
  `--allow-privileged` with a confirmation for dangerous environments (in both `up` and `new`).
- `mcp/`: reject any plan or `range.yaml` that contains a dangerous environment.
- `catalog/`: store the dangerous flag (with its reasons) and the image platforms in the index.
- `validate/`: reuse the spike's checks as post-`up` probes: attacker → each declared service by
  name, and that no target has a default route.

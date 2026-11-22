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
6. **`--expose` and `--proxy` publish on `127.0.0.1` only**, through a relay on a separate
   network that is not internal. Targets never join it. An address that is empty or `0.0.0.0` is
   a bug. See [Proxy and expose](#proxy-and-expose).
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

### Catalog overrides

Some upstream environments have quirks that the compose file does not show. They are corrected
in `data/catalog-overrides.yaml`, a data-only file that `python -m sosya.catalog.build index`
applies to the index. Every entry names the environment, service and port it changes and gives
its reason; the build fails on an entry that points to an environment, a service or a port that
does not exist, so a new Vulhub pin cannot leave a stale override behind.

First entry: port 50000 of `jenkins/CVE-2017-1000353` (the Jenkins agent port) is published by
the compose file but never listens. At Gate 2 it cost a repair attempt. It is now **optional**:
in `sosya validate`, an optional port that does not answer is a warning, not a failure, so it
never goes back to the LLM. `sosya catalog` shows optional ports with a `?`.

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
  The effort goes out as `reasoning_effort` (`xhigh` and `max` become `high`). A 400 or 422
  about it drops the field for the rest of the process. A server on this machine (loopback or
  `host.docker.internal`) gets a 30-minute read timeout instead of 5 minutes, because a model on
  CPU can need several minutes for one answer, and a timeout would only send the same request
  again. Ollama cuts a prompt longer than its context window without an error. When
  `usage.prompt_tokens` is below half of an estimate of what was sent (characters / 4, only for
  prompts above about 1000 tokens), the completion carries a warning, which `sosya new` prints
  as a `warn` line: the server probably truncated the prompt.
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

## Planner

1. **Queries.** The LLM turns the sentence into 1 to 8 catalog keywords (`QueryPlan`) at low
   effort: it is a simple task, and its latency adds
   to every `sosya new`.
2. **Candidates.** `sosya.catalog.search` ranks entries for the sentence and the keywords with
   Reciprocal Rank Fusion. From the ranking, at most 25 candidates are kept:
   - entries whose images cannot run on the engine's platform, or whose platform is unknown,
     are dropped; entries that run only under emulation stay, marked as such;
   - dangerous entries are dropped unless the user's own sentence names them by path or CVE
     id. A keyword the LLM made up never counts.
   - on equal relevance, the 230 image-only entries rank before the 104 that need local files
     from the Vulhub checkout. This tiebreak applies in every per-query ranking and in the fused
     order, so `sosya catalog` sorts the same way.
3. **Draft.** The LLM writes a `PlanDraft` from the candidates, which are listed in the prompt.
   Entries that need local files carry a `[local files]` mark, and the system prompt tells
   the LLM to prefer the others when they fit the description equally well.
   The schema is fixed: there is no enum of candidate ids, and no `flag` (flag paths are not the
   LLM's choice). The draft becomes a `range.yaml` mapping and goes through the same checks as
   a hand-written file: the range schema, `check_catalog`, and "the component is one of the
   candidates". Each failure is an `Issue` that goes back to the LLM.
4. **Name.** The first draft fixes the range name; later drafts keep it.
5. **No spoilers outside the hints** (`sosya.advisories`). Advisory ids (CVE, GHSA, CNVD,
   CNNVD, Struts `S2-NNN`) stay out of the name, the description and the objectives, unless the
   user's sentence already names them; SCENARIO.md keeps them for hint 3. The system prompt says
   so. The name is cleaned in code, deterministically, before `unique_name`
   (`jenkins-cve-2017-1000353` becomes `jenkins`; a name left empty takes the first host's
   name). An id in the description or an objective is a static issue that goes to repair. A
   name the user types in the plan editor is not touched.
6. **Dangerous entries** in a draft are not repaired: the build stops on them (see
   [Services with host-level privileges](#services-with-host-level-privileges)).

## Flags and SCENARIO.md

- **Flags.** Every `sosya up` writes a new random flag, `SOSYA{<32 hex>}`, on every host, in
  its primary container, and stores it in `.sosya/state.json`. It is never printed.
- **Injection** uses `docker cp -` with an in-memory tar archive, so it needs no shell in the
  target. The archive holds only the file (mode 0644, root), never a directory entry, so the
  owner and mode of `/root`, `/tmp` or `/data` do not change. World-readable on purpose:
  several environments only give a file read or a shell that is not root.
- **Path.** `flag:` in `range.yaml` (an override for hand-written ranges; the planner never sets
  it), else `/flag.txt`. If the copy fails (missing directory, read-only root filesystem), the
  flag goes to `/tmp/flag.txt`. If that fails too, `up` warns and `sosya validate` fails that
  host.
- **SCENARIO.md** is deterministic: it is generated from `range.yaml` and the catalog, with no
  LLM call. It holds the description, objectives, network map, hosts with the actual flag
  paths (never the values), and progressive hints in closed `<details>` blocks, three per host:
  1. what runs there: the product, its kind (the category tags: Framework, Webserver,
     Database, CMS, Message Queue, LLM) and the published services with their ports. The title
     is not shown, because Vulhub titles often contain the CVE;
  2. the class of the vulnerability, from the catalog's vulnerability tags (RCE, Path
     Traversal, Auth Bypass, Deserialization, ...), never a CVE. The 7 entries that have only
     category tags get a fixed line that points to hint 3;
  3. the spoiler: the title, the CVE links, the Vulhub page at the pinned commit and the
     references.

  A host that shares no network with the attacker box gets one more block first, "The way in":
  the hosts to pivot through and the network each one opens. It comes from a breadth-first
  search over the networks (`topology.routes`). `sosya up` writes SCENARIO.md next to the
  compose file and prints its path with `sosya shell <name>`.

## Live validation

`sosya validate <range>` (also run by `sosya new`, and by CI on the gallery) checks a running
range. The CI integration test calls the same function, so every user's range gets the same
isolation checks as CI.

| Group | Check | Pass when |
| --- | --- | --- |
| service | every container | running (healthy, with a healthcheck), or exited 0 (one-shot) |
| reach | attacker → every service on a shared network, by name and by IP, each TCP port | connects within 90 s; an optional port only warns |
| segmentation | attacker → containers on no shared network, by name and by IP | unresolved or refused |
| no internet | every target namespace: DNS, TCP v4 and v6, HTTP, default route | all fail |
| host isolation | published ports; host → every target IP and port | none; refused |
| exposure | with `--proxy`/`--expose`: see [Proxy and expose](#proxy-and-expose) | all hold |
| attacker | `net.ipv4.ip_forward` | `0` |
| attacker | internet access, when `internet: true` | warning only: never fails the range, never sent to the LLM |
| flag | `docker cp` of each flag | the value recorded at `up` |

Speed matters, because `validate` runs in the demo: all the checks of a network namespace go
into one shell script, so the attacker costs one `docker exec` and each target one
`docker run --rm --network container:<id>`. Targets are probed with the attacker image, which
is already present and has the tools; the target image may have none, and nothing extra is
pulled. Readiness retries run inside the script, and the namespaces run in parallel. The
dmz-redis range validates 25 checks in about 3 seconds. The exit code is 1 when a check fails.

### One-shot services

Some environments have a service that runs once and exits, such as `airflow-init` or the
`initd` of `couchdb/CVE-2017-12635`. Measured with Compose v5.8.0: `up --wait` already treats
an exit code of 0 as done and keeps waiting for the other services. For other Compose versions,
`sosya up` does not trust a failed `up --wait` on its own: if every stopped container exited
with 0, it keeps polling the others until the same deadline, and fails only on an exit code
other than 0, an unhealthy service or the deadline. `sosya validate` counts an exit code of 0 as
a success.

## Repair loop

`sosya new` (`sosya.build.build`) gets at most **3 attempts in all**, static and live failures
together:

1. draft the range; static issues (schema, catalog, "not a candidate") go back to the LLM;
2. otherwise start it from `.sosya/ranges/<name>/attempts/<n>/range.yaml`; a range that does
   not start is a live problem;
3. validate it; failed checks go back to the LLM with the last 30 log lines of every service of
   the hosts involved. Warnings never go back.

Before the first start, `sosya new` shows the plan and asks `Start this range? [Y/n/edit]`
(`--yes` skips it). With `e` the plan opens as `range.yaml` in `$VISUAL` or `$EDITOR`. On save it
goes through `load_range` and `check_catalog`, the checks of `sosya up`, with any catalog id
allowed. If it has errors, they are printed, written at the top of the file as `# sosya:`
comments, and the editor opens again. An emptied file discards the edits. Otherwise the preview
comes back with the edited range, and that is the one that starts. A dangerous component in an
edit follows the draft rules: without `--allow-privileged` the build stops with the same message,
and with it a confirmation is still needed. If the edited range fails live, the next repair
request starts with the edited lab, so the LLM repairs what actually ran. The components the
user chose stay allowed in the repairs.

Every failed attempt is stopped before the next one and kept in
`.sosya/ranges/<name>/attempts/<n>/` (`range.yaml` or `draft.json`, `issues.json`, `logs.txt`,
`docker-compose.yml`). `sosya down` deletes everything in the range directory except
`attempts/`.

Failures of the machine stop the build at once, without repair, because another component would
not fix them: Docker Hub's pull limit (`toomanyrequests`), no network, a full disk, no free
subnets, an unreachable or too old daemon, an unreachable LLM API
(`runtime.HostEnvironmentError`). An image that does not exist (`manifest unknown`, `not
found`, `pull access denied`) is the component's problem and goes to repair. A refusal from the
model stops the build with a clear message.

The first draft that has a name fixes it for every attempt. If `ranges/<name>/` exists, or a
range of that name is recorded or running, the range becomes `<name>-2`, `<name>-3`, ...
(within the 40-character limit), and the output says so. A green range is published to
`ranges/<name>/range.yaml` and `ranges/<name>/SCENARIO.md`, and the state points at that file,
so `sosya up`, `down` and `validate` work with the name.

## Gate 2 (2026-11-21)

Ten fixed prompts in `evals/gate2.yaml`, run with `evals/run.py` (Anthropic, sonnet line).

- **Effort sweep** (planning only, no Docker): low, medium and high all gave 10/10 valid plans
  that met their expectations, at about 5.3 s median for queries and plan together. High had
  the worst tail (7.7 s p90). Default: **medium**. Queries always use low.
- **Full run** at medium effort: **10/10 green**, no refusals; 71 s median and 240 s p90 to a
  green range, mostly image pulls on a cold cache (the GIF prompt, with warm images: 11 s).
  Two prompts needed the repair loop, once each: a DNS name clash found statically, and a
  Jenkins agent port (50000) that never answered, after which the LLM picked another Jenkins
  environment.

Reports: `evals/reports/gate2-plan-20261121-152805.md` and `evals/reports/gate2-20261121-153128.md`.

**Rerun after the local-files preference** (2026-11-22, planning only, medium): still **10/10**
valid plans with their expectations met, every one on the first attempt, 5.3 s median and
6.7 s p90. Before the change, 3 of the 10 plans used environments with local files; now none
does. `pivot` and `three-hosts` swapped `phpmyadmin/CVE-2018-12613` and `git/CVE-2017-8386` for
image-only environments. `local-files` ("a PHP application vulnerable to local file
inclusion") now gets `thinkphp/lang-rce`, a ThinkPHP file inclusion, instead of `php/inclusion`.
That still fits the sentence, but it means the Gate 2 prompts no longer start an environment
with local files. That path stays covered by `tests/integration/test_local_files.py`.
Report: `evals/reports/gate2-plan-20261121-232328.md`.

### Local models: Ollama on CPU (2026-11-22)

Qwen3 8B on Ollama 0.40, CPU only (12 cores, no GPU), 16k context, at about 3.7 to 5.4 output
tokens per second. The endpoint was given only as `OPENAI_BASE_URL=http://localhost:11434/v1`,
with no key and no `SOSYA_MODEL`: the adapter picked the only listed model, and `json_schema`
structured output worked without the text fallback. The planning prompt is about 3,100 tokens,
far below the context, so no prompt was truncated.

| Run | Valid plans | Expectations | Time per prompt |
| --- | --- | --- | --- |
| default effort (medium: thinking on), before the fixes, 1 prompt | 1/1 | 1/1 | 604 s |
| `none` (thinking off), all 10 prompts | 3/10 | 3 of the valid ones | 292 s median, 391 s p90 |
| `none`, 3 prompts again | 1/3 | 1/3 | 162 s median |
| medium (thinking on), the same 3 prompts | 3/3 | 2/3 | 596 s median, 784 s p90 |

- **Speed.** With thinking on, the queries call alone takes about 90 s (500 thinking tokens for
  a few keywords), and a plan 5 to 12 minutes. Before the fixes, the 5-minute read timeout cut
  a plan call, and the retry ran it again from the start.
- **Quality with `none`.** It is fast, but the 8B model misreads the request. It copies
  `struts2(8080)` from the candidate list as a service name, adds the attacker box as a host,
  or writes a component without the `vulhub/` prefix. Three attempts do not fix it.
- **Quality with thinking.** The plans are valid, usually on the first attempt. One of 3 missed
  the pivot that the sentence asked for.
- **Full run.** `sosya new "A Jenkins server with a remote code execution bug" --yes` at the
  default effort: green in **15 min 27 s**, 14/14 checks, one attempt
  (`jenkins/CVE-2017-1000353`). The model named the range after the CVE.

**`none` was removed on 2026-11-22.** It was an experiment outside the v0.1 specification, and
with the 8B model it gave 3 valid plans of 10. `--effort` now accepts low, medium, high, xhigh and
max. Turning a local model's thinking off (on Ollama `/v1` only `reasoning_effort: "none"` does;
`low` still thinks and `think: false` is ignored) is planned for v0.2 as a provider-specific option.

What this means for the README: a local 8B model on CPU **works**, but slowly. Use the default
effort, and count on 10 to 15 minutes for a single-host range. Each local result above is one run of one model.

Reports: `evals/reports/gate2-plan-20261121-232502.md` (before the fixes),
`gate2-plan-20261121-234120.md` (`none`, 10 prompts), `gate2-plan-20261122-002814.md` (`none`
and medium, 3 prompts).

## Proxy and expose

`sosya up --proxy [--proxy-port 1080]` adds a SOCKS5 proxy for the host's browser or Burp;
`--expose HOST:PORT[:LOCAL_PORT]` (repeatable) publishes one service. Both publish on
`127.0.0.1` only and print one warning line per forward: there is no confirmation prompt, which
stays reserved for dangerous environments. Measured on Engine 29.10 (2026-11-21).

```
host 127.0.0.1:P ──► relay ── network `proxy`: plain bridge, IPv6 off, only the relay,
                       │      ports 127.0.0.1:P:P
                       ▼ network `relay`: internal, gateway isolated, IPv6 off
                 attacker-relay (network_mode: service:attacker)
                   microsocks and socat bound ONLY to the attacker box's `relay` address
                       ▼ the attacker box's own segments
                     targets
```

Invariants:

1. **127.0.0.1 only**, never every interface, in IPv4 or IPv6: the renderer writes
   `127.0.0.1:P:P` and asserts it; the `proxy` network has IPv6 off.
2. **Targets never join a network that is not internal.** Only the relay joins `proxy`; it joins
   no segment.
3. **The proxy reaches only what the attacker box reaches**: microsocks runs in the box's
   network namespace and resolves names with its DNS. With `internet: false` the box joins only
   internal networks (`relay` included), so it has no default route and the proxy gives no
   internet. `--expose` goes through the attacker box as well, so it accepts only services the
   box reaches.
4. **Targets cannot use the proxy or the relay.** The forwarder listens only on the box's
   address on `relay`, which no target joins; nothing listens on the box's segment addresses.
   The relay sets `ip_forward=0` and listens only on its `proxy` address (the one with the
   default route).

The two containers use the attacker image (`sosya-forward`, `sosya-relay`, with `socat` and
`microsocks`) and are healthy only once every listener is up, so `up --wait` waits for them.
`relay`, `attacker-relay` and `attacker-link` are reserved host names, `relay` a reserved
network name. The state records `proxy_port` and `exposes`; before starting, `up` fails if a
local port is taken, unless the range's own relay holds it.

`sosya validate` adds the group `exposure`:

| Check | Pass when |
| --- | --- |
| `relay`, `attacker-relay` | running and healthy |
| relay ports | every binding is `127.0.0.1`, exactly the expected ports; no binding on the attacker box or the forwarder |
| host → `127.0.0.1:P` | answers |
| host → `[::1]:P` and the host's own addresses (spike check 5) | refused |
| proxy → every service the attacker box shares a network with | SOCKS5 CONNECT succeeds (an optional port only warns) |
| proxy → `1.1.1.1:443`, `example.com:443`, with `internet: false` | refused |
| `127.0.0.1:L` → each forward | the service answers (the connection stays open or sends a banner) |
| every target → the relay and the attacker box, on every address and port | blocked, run in the target's namespace script |

## Attacker image

`ghcr.io/gabrielemontagnini/sosya-attacker:<version>`, for linux/amd64 and linux/arm64, built
by `.github/workflows/attacker.yml` on native runners (`ubuntu-24.04` and `ubuntu-24.04-arm`,
no QEMU). Each build uses a `docker-container` builder, whose BuildKit image is pinned by tag
and digest like the actions (`moby/buildkit:v0.34.2@sha256:...`), and pushes by digest with OCI media
types (`oci-mediatypes=true`), because a Docker manifest list cannot carry annotations; the
smoke test pulls the published image back by digest, since that builder does not load it
locally. The merge job joins the two digests into one OCI index tagged `<version>`, annotated
with `org.opencontainers.image.source`, which links the package to the repository, and checks
that the index is OCI and holds linux/amd64 and linux/arm64.
`release.yml` calls it after checking that the tag matches `__version__`, and the PyPI job
`needs:` it, so PyPI never gets a version without its image. It also runs by hand
(`workflow_dispatch`). The package is public: anonymous pulls work. Compressed pull size, from
`docker buildx imagetools inspect --raw` (config plus layers, gzip; measured 2026-11-22 on
`0.0.1`): **177.0 MB for linux/amd64** and **172.7 MB for linux/arm64**, about 53 MB of which is
the Kali base. Accepted for Gate 3.

## MCP server

`sosya mcp` (`sosya.mcp`) is a thin layer over the functions the CLI uses (`sosya.mcp.tools`),
built with the official MCP Python SDK (2.x) and served on stdio.

| Tool | What it does |
| --- | --- |
| `catalog_search` | ids, titles, CVEs, ports (with `optional`), platforms, `runnable` and `emulated` for the engine; dangerous entries never appear, even when named |
| `check_range` | a `range.yaml` written by the agent: the range schema and `check_catalog`, with the same issues as the repair loop, so an agent can plan without an LLM key |
| `up` | a `range.yaml` or a gallery name; pulls and starts with progress notifications |
| `status`, `validate`, `down`, `scenario` | as the CLI; `scenario` returns SCENARIO.md |
| `new` | registered only when the environment names an LLM provider (no network call at start: the model is chosen at the first call) |
| `attacker_exec` | a command in the attacker box, only when the range has `attacker.internet: false` **and** every network the live box joins is internal |
| `check_flag` | right or wrong, compared in constant time; never the value |

Rules:

- **Dangerous environments are always refused** (see
  [Services with host-level privileges](#services-with-host-level-privileges)). No tool has an
  `allow_privileged` argument; `runtime.up` and `build.build` always get `False`.
- **Flag values never appear** in a result or a progress message: recorded values and anything
  shaped like `SOSYA{...}` become `SOSYA{redacted}`. The exception is the output of
  `attacker_exec`: a flag only appears there after a real exploit, and the agent must be able to
  prove the capture, which `check_flag` then confirms.
- **Errors are issues.** Every result has `ok` and `issues` (`level`, `message`, `host`) and is
  marked as an MCP error when `ok` is false; an unexpected exception becomes an issue too, with
  the traceback on stderr.
- **Fixed workspace.** MCP clients start servers from arbitrary, sometimes read-only, working
  directories (even `/`), so the server never uses the current directory: it works in
  `SOSYA_WORKSPACE`, else `--workspace`, else `$XDG_STATE_HOME/sosya` (`~/.local/state/sosya`).
  An agent's `range.yaml` is kept in `mcp/<name>/range.yaml` there, outside the range directory
  that `down` deletes. Ranges started over MCP carry the usual labels, so `sosya status` and
  `sosya down` find them from any directory.
- **stdout is the protocol.** Tools never print; every Docker call captures its output; logs go
  to stderr. A test starts the server on real stdio with a noisy fake `docker` and checks that
  every line on stdout is a JSON-RPC 2.0 message.
- Progress: the runtime's one-line steps (one per pulled image) become progress notifications.
  MCP log notifications are not used: they are deprecated in the current protocol version.

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
- `mcp/`: reject any plan or `range.yaml` that contains a dangerous environment (see [MCP server](#mcp-server)).
- `catalog/`: store the dangerous flag (with its reasons) and the image platforms in the index.
- `validate/`: see [Live validation](#live-validation). CI runs every `@pytest.mark.docker` test on
  ubuntu-latest (job `docker`), installing docker-ce when the runner's Engine is older than 28,
  with the attacker image always built from the commit's own Dockerfile.

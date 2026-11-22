# The `range.yaml` format

A range is one file, `range.yaml` (`apiVersion: sosya/v1`). `sosya new` writes it with an LLM,
but you can write it by hand, share it, and start it anywhere with `sosya up`, with no LLM key.
An MCP client can pass one too (`check_range`, then `up`).

`sosya up <target>` looks for the file in this order: a path (a `range.yaml` or a directory that
holds one), a range already recorded in this workspace, `ranges/<name>/range.yaml`, then the
gallery.

The schema is the Pydantic model in
[`src/sosya/spec.py`](../src/sosya/spec.py) (`RangeSpec`, `Host`, `Attacker`). Unknown keys are
errors, not warnings, so a typo never goes unnoticed.

## Fields

### Top level

| Field | Type | Required | Rules |
| --- | --- | --- | --- |
| `apiVersion` | string | yes | Exactly `sosya/v1`. |
| `name` | string | yes | Lowercase letters, digits and `-`; starts with a letter, does not end with `-`; at most 40 characters. It names the Compose project and the range in `sosya status`. |
| `description` | string | no | One line for people. Default: empty. |
| `networks` | list of names | yes | At least one. The scenario networks (segments). Each name must be unique, not reserved, and used by at least one host or by the attacker. |
| `hosts` | list of hosts | yes | At least one. See below. |
| `attacker` | object | yes | The Kali attacker box. See below. |
| `objectives` | list of strings | no | What the player should achieve; copied into `SCENARIO.md`. Default: none. |

### `hosts[]`

| Field | Type | Required | Rules |
| --- | --- | --- | --- |
| `name` | string | yes | Lowercase letters, digits and `-`; starts with a letter, does not end with `-`; at most 32 characters. Unique, not reserved. It becomes the host's DNS name inside the range. |
| `component` | string | yes | A catalog id, always with the `vulhub/` prefix: `vulhub/<product>/<environment>`. |
| `networks` | list of names | yes | At least one, no duplicates, each declared in the top-level `networks`. |
| `service` | string | no | For components with several services: the one that takes the host's name. Default: the first service that publishes ports. |
| `flag` | string | no | Absolute path where the flag is written. Default: `/flag.txt`. |

### `attacker`

| Field | Type | Required | Rules |
| --- | --- | --- | --- |
| `networks` | list of names | yes | At least one, no duplicates, each declared. It must share a network with at least one host, or nothing would be reachable. |
| `internet` | boolean | no | Default `true`. See below. |

## Names, networks and services

### Reserved names

Sosya uses some names for its own containers and networks, so a range cannot:

- **networks**: `egress`, `proxy`, `expose`, `relay`;
- **hosts**: `attacker`, `relay`, `attacker-relay`, `attacker-link`.

Two more kinds of names are generated, and `sosya` reports a clash with them as an error:

- a component with two or more services gets a private network named `<host>-net`, so do not name
  a scenario network `web-net` if a host called `web` has several services;
- the secondary services of a component become `<host>-<service>` (for example `blog-mysql`), so
  do not give another host that name.

### Networks

Every network in `networks` is a Docker network with `internal: true`: it has no route to the
internet or to your host. A host on two networks is the only path between them, which is how a
pivot works:

```yaml
networks: [dmz, internal]
hosts:
  - name: web
    networks: [dmz, internal]   # dual-homed: the pivot
  - name: cache
    networks: [internal]        # reachable only from web
attacker:
  networks: [dmz]               # the attacker starts in the DMZ
```

### Services of a component

Many Vulhub environments have several services (an application and its database, for example).
Sosya keeps them together:

- the **primary service** takes the host's name and joins the host's networks. It is the one in
  `service:`, or else the first service that publishes ports in the Vulhub compose file;
- the **other services** that Vulhub publishes also join the host's networks, as
  `<host>-<service>`;
- services that Vulhub does not publish (a database, usually) stay on the private network
  `<host>-net`, where they keep their original Vulhub names, so the application finds them as
  before. The attacker cannot reach them directly.

`sosya catalog --json <query>` lists the services of each environment and their ports.

### Flags

Every host gets a random flag (`SOSYA{...}`) when the range starts, written into its primary
container with `docker cp` (readable by every user, mode `0644`). The default path is
`/flag.txt`; set `flag:` to put it somewhere that fits the scenario, for example `/root/flag.txt`
or `/data/flag.txt`. If the path cannot be written, Sosya falls back to `/tmp/flag.txt`.
`SCENARIO.md` lists where each flag is; the values are never printed.

### `attacker.internet`

The attacker box joins the networks in `attacker.networks`. With `internet: true` (the default) it
also joins a separate `egress` network, so you can install tools or receive callbacks from the
internet. Targets never join that network.

Set `internet: false` for a fully closed range. Over MCP, `attacker_exec` works only in such ranges,
so an AI agent never gets a box with internet access.

## Finding component ids

Search the catalog with `sosya catalog`. Each argument is a separate query and the results are
merged:

```console
$ sosya catalog wordpress
$ sosya catalog jenkins gitlab
$ sosya catalog "java deserialization"
$ sosya catalog CVE-2021-44228
```

The *Environment* column shows `<product>/<environment>`. In `range.yaml`, add the `vulhub/`
prefix: `wordpress/pwnscriptum` becomes `component: vulhub/wordpress/pwnscriptum`. The *Notes*
column warns about environments that need extra care:

- **⚠ privileged**: a dangerous environment that starts only with `--allow-privileged` and a
  confirmation, and never over MCP;
- **amd64 only**: images that run only under emulation on your machine;
- **local files**: the environment needs files from the Vulhub repository, which Sosya downloads
  on the first start (it needs `git`);
- **platform unknown**: an image that cannot be pulled; the range will not start.

`sosya catalog --json` gives the full entry: CVEs, references, services, images, ports and
platforms.

## A commented example

```yaml
apiVersion: sosya/v1             # always sosya/v1
name: dmz-redis                  # the range's name, used by up, down, status and shell
description: Struts2 in a DMZ, passwordless Redis only on the internal network

networks: [dmz, internal]        # two segments, both internal: no internet, no host access

hosts:
  - name: web                    # DNS name inside the range: http://web:8080
    component: vulhub/struts2/s2-045
    networks: [dmz, internal]    # on both segments: the only way from dmz to internal
    flag: /root/flag.txt         # where this host's flag is written

  - name: cache
    component: vulhub/redis/4-unacc
    networks: [internal]         # the attacker box cannot reach it directly
    flag: /data/flag.txt

attacker:
  networks: [dmz]                # sosya shell starts here
  internet: true                 # the attacker box (never a target) can reach the internet

objectives:                      # shown in SCENARIO.md, with hints and CVE links
  - Get a shell on web
  - Pivot from web to cache and read the flag
```

Start it with `sosya up path/to/range.yaml`: the file is checked against the schema and the
catalog before anything starts. Then `sosya validate dmz-redis` re-runs every live check. Over
MCP, `check_range` runs the same checks without starting anything. The gallery in
[`src/sosya/gallery/`](../src/sosya/gallery/) has seven complete examples.

## Errors

Errors say what to change, and name the field when the problem is in one field, for example:

```
range.yaml is not a valid range:
  host cache joins undeclared networks: backend
```

Checks against the catalog come after the schema: an unknown component gets a suggestion
(`Did you mean vulhub/redis/4-unacc?`), a `service:` that the component does not have lists the
ones it does, and an image that cannot run on your machine's platform is an error.

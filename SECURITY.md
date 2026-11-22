# Security policy

Sosya runs deliberately vulnerable software on your machine. Its own job is to keep that software
contained. A flaw in that containment is the most serious bug Sosya can have, and it should be
reported privately.

## How to report a vulnerability

Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/gabrielemontagnini/sosya/security/advisories/new)
(the *Security* tab of the repository, then *Report a vulnerability*).

Please do not open a public issue, pull request or discussion for a vulnerability.

A useful report includes:

- the output of `sosya --version` and `sosya doctor`;
- the `range.yaml` involved, or the gallery range name;
- the exact commands you ran, and what you observed (for example the `docker inspect` output of a
  network or a container);
- your operating system and Docker version, if `sosya doctor` does not show them.

Never include API keys or tokens. `sosya doctor` prints only the names of the variables that are
set, not their values.

## Scope

**In scope: the code of Sosya**, and above all **any way to break the isolation** it promises:

- a target container that reaches the internet, the host, or a network outside its range;
- a port published on anything other than `127.0.0.1`, with or without `--expose` and `--proxy`;
- a target that joins a non-internal Docker network;
- a path between two segments of a range that does not go through a dual-homed host;
- an MCP tool that bypasses the rules: a dangerous (`privileged`) environment started over MCP,
  `attacker_exec` in a range whose attacker box has internet access, or a tool that acts on files
  or ranges outside its workspace;
- a `range.yaml` (hand-written, from the LLM, or from an MCP client) that passes validation but
  makes the renderer produce something the catalog does not contain;
- a key or token that Sosya prints or writes to a log, a report or a file;
- the checks of `sosya validate` reporting green on a range that is not isolated.

**Out of scope:**

- **Vulnerabilities of the Vulhub environments.** They are there on purpose: exploiting a target
  inside a range is the point of a range. Problems with an environment itself (an image that no
  longer exists, a service that does not start) are ordinary issues: use the *Environment broken
  upstream* issue form.
- Container escapes made possible by a dangerous environment that you started with
  `--allow-privileged` and confirmed. Those environments ask for consent because they make an
  escape trivial.
- The limit stated in the README: containers share the host's kernel, so a kernel bug can lead to
  an escape. That is a property of Docker, not of Sosya. Run sensitive labs on a dedicated machine
  or in a VM.
- What you do from the attacker box against targets you own: Sosya builds labs, it does not police
  them.

If you are not sure whether something is in scope, report it privately anyway.

## Supported versions

Only the latest minor release receives security fixes. Today that is **0.1.x**. Fixes ship as a
new patch release; older releases are not patched.

## Response times

Sosya is maintained by one person, so these are best-effort targets, not guarantees:

- acknowledgement of your report within **7 days**;
- a first assessment (confirmed, needs more information, or out of scope) within **14 days**;
- a fixed release within **90 days** of confirmation, sooner for isolation breaks.

I will keep you informed in the advisory thread, agree on a disclosure date with you, and credit
you in the advisory and the release notes unless you prefer otherwise.

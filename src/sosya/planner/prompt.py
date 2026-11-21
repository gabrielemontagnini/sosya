"""The planner's prompts. The system prompts are fixed text, so the provider can cache them."""

from collections.abc import Sequence

from sosya.planner.candidates import Candidate
from sosya.planner.schema import MAX_QUERIES

QUERY_SYSTEM = f"""\
You help build isolated training labs from a fixed catalog of documented, vulnerable Docker
environments (Vulhub). Turn the user's description of a lab into short search keywords for that
catalog: product names (for example jenkins, struts2, redis), CVE ids, and technology words (for
example deserialization, ssti, sql). Give 1 to {MAX_QUERIES} keywords, most important first. Write
them in English, whatever the language of the description. Do not add explanations."""

PLAN_SYSTEM = """\
You compose isolated cyber-range labs for security training. A lab is built only from the
catalog environments listed in the request; you never write code, exploits or attack steps.

Write the lab as JSON with these rules:
- name: lowercase letters, digits and hyphens, starting with a letter, at most 40 characters.
- networks: the lab's network segments (for example dmz, internal), lowercase slugs. Do not use
  the reserved names egress, proxy or expose. Every network must be used.
- hosts: one entry per target. name is a lowercase slug, unique, never "attacker". component is
  exactly one of the candidate ids. networks lists the segments the host joins. service is null,
  unless the environment has several services and a specific one must take the host's name.
- attacker: the attacker box. It joins only the segments the trainee starts from, and must share
  at least one segment with a host. internet is true unless the user asks for an offline lab.
- Pivoting: a host on two segments is the only path between them. To make a target reachable
  only after a pivot, put it on a segment the attacker does not join, and put another host on
  both segments.
- Use the fewest hosts that satisfy the description. Prefer environments that do not run under
  emulation.
- objectives: 1 to 4 short goals for the trainee, such as "Get a shell on web" or "Read the flag
  on cache". Goals only, never instructions on how to attack.
- description: one sentence that says what the lab contains."""


def _candidate_line(candidate: Candidate) -> str:
    entry = candidate.entry
    parts = [entry.id, f"title: {entry.title}"]
    if entry.cves:
        parts.append("cves: " + ", ".join(entry.cves))
    services = []
    for service in entry.services:
        ports = ",".join(str(p.port) for p in service.ports)
        services.append(f"{service.name}({ports})" if ports else service.name)
    parts.append("services: " + " ".join(services))
    summary = " ".join(entry.summary.split())[:160]
    if summary:
        parts.append(f"summary: {summary}")
    if candidate.emulated:
        parts.append("[emulated: slow on this machine]")
    return "- " + " | ".join(parts)


def plan_request(sentence: str, candidates: Sequence[Candidate]) -> str:
    lines = "\n".join(_candidate_line(c) for c in candidates)
    return (
        f"Lab description:\n{sentence}\n\n"
        f"Candidate environments (use only these ids as component):\n{lines}"
    )


def repair_request(problems: Sequence[str]) -> str:
    listed = "\n".join(f"- {problem}" for problem in problems)
    return (
        "The lab you wrote did not pass Sosya's checks. Write the whole lab again, fixing these "
        "problems. Keep the same name. You may replace a component with another candidate.\n"
        f"{listed}"
    )

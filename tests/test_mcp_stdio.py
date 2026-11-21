"""`sosya mcp` on real stdio: stdout carries only JSON-RPC messages, even during `up`.

The server runs as a subprocess with a fake `docker` first on the PATH. The fake writes noise to
its own stdout and stderr on every call, so a Docker call that did not capture its output would
show up on the protocol stream.
"""

import json
import os
import shlex
import sys
from pathlib import Path

import anyio
from mcp import Client, StdioServerParameters

FAKE_DOCKER = """\
#!{python}
import sys
args = sys.argv[1:]
print("fake docker noise on stderr", file=sys.stderr)
if args[:1] == ["version"]:
    print("29.10.0")
elif args[:1] == ["info"]:
    print("linux/x86_64")
elif args[:1] not in (["ps"], ["inspect"]):
    print("fake docker noise on stdout", args)  # compose, pull, image inspect, cp, ...
sys.exit(0)
"""


def test_stdout_carries_only_json_rpc(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER.format(python=sys.executable))
    docker.chmod(0o755)
    wire = tmp_path / "stdout.log"
    server = f"{shlex.quote(sys.executable)} -m sosya mcp | tee {shlex.quote(str(wire))}"
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(tmp_path / "home"),
        "SOSYA_WORKSPACE": str(tmp_path / "workspace"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
        "SOSYA_ATTACKER_IMAGE": "sosya-attacker:test",
    }
    params = StdioServerParameters(command="sh", args=["-c", server], env=env, cwd=str(tmp_path))
    progress: list[str] = []

    async def on_progress(value: float, total: float | None, message: str | None) -> None:
        progress.append(message or "")

    async def session() -> tuple[set[str], dict]:
        async with Client(params) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            result = await client.call_tool(
                "up", {"gallery": "dmz-redis"}, progress_callback=on_progress
            )
            return names, result.structured_content or {}

    names, result = anyio.run(session)
    assert "up" in names and "new" not in names
    assert result["ok"], result
    assert any("range dmz-redis is up" in message for message in progress)
    assert (tmp_path / "workspace" / ".sosya" / "state.json").is_file()
    assert not (tmp_path / ".sosya").exists()

    lines = [line for line in wire.read_text().splitlines() if line.strip()]
    assert lines
    for line in lines:
        message = json.loads(line)  # anything else on stdout breaks the protocol
        assert message.get("jsonrpc") == "2.0", line
    assert "noise" not in wire.read_text()

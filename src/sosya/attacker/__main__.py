"""Development only: `python -m sosya.attacker build` builds the attacker box image locally."""

import subprocess
import sys

from sosya.attacker import build_command, build_context, image


def main(argv: list[str]) -> int:
    if argv != ["build"]:
        print("usage: python -m sosya.attacker build", file=sys.stderr)
        return 2
    with build_context() as context:
        return subprocess.run(build_command(image(), context), check=False).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

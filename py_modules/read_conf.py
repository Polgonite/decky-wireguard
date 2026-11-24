"""Read one selected file in a process already running as the desktop user."""

import os
import stat
import sys


def main(path: str) -> int:
    if os.geteuid() == 0:
        return 1
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY), "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            return 1
        content = source.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        return 1
    sys.stdout.buffer.write(content.decode("utf-8-sig").encode("utf-8"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1]))
    except (OSError, ValueError):
        sys.exit(1)

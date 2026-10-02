#!/usr/bin/env python3
"""Restricted SSH forced command: stream one canonical QCOW2 from the Nix store."""

import os
from pathlib import Path
import re
import stat
import sys

CHUNK_BYTES = 65536
IMAGE_PATH = r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._-]+/[A-Za-z0-9._-]+[.]qcow2"


def parse_command(command):
    if not isinstance(command, str) or not re.fullmatch(r"qcl-negf-image-read " + IMAGE_PATH, command):
        raise ValueError("Only qcl-negf-image-read of one Nix-store QCOW2 is permitted")
    return Path(command.split(" ", 1)[1])


def stream_image(path, output):
    path = Path(path)
    if path.resolve(strict=True) != path or path.is_symlink():
        raise ValueError("Image must be a canonical path without symlinks")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 72:
            raise ValueError("Image must be a nonempty regular QCOW2 file")
        total = 0
        while block := source.read(CHUNK_BYTES):
            output.write(block)
            total += len(block)
        output.flush()
        if total != metadata.st_size:
            raise ValueError("Image changed size during transfer")


def main():
    if len(sys.argv) != 1:
        raise ValueError("This program is an SSH forced command and accepts no arguments")
    stream_image(parse_command(os.environ.get("SSH_ORIGINAL_COMMAND", "")), sys.stdout.buffer)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"Image reader rejected request: {error}", file=sys.stderr)
        sys.exit(1)

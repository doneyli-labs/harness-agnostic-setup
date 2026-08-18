#!/usr/bin/env python3
"""Fail-closed command shell for the skill portability auditor."""
import argparse
import os
import sys

try:
    import pwd
except ModuleNotFoundError as error:
    if error.name != "pwd":
        raise
    pwd = None


class OperationalError(RuntimeError):
    """An operational refusal whose message is safe to print."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise OperationalError("CLI_INVALID")


def _member(function, capability):
    return callable(function) and function in capability


def _capable():
    functions = {name: getattr(os, name, None) for name in
                 ("open", "stat", "readlink", "link", "unlink", "scandir")}
    dir_fd = getattr(os, "supports_dir_fd", ()) or ()
    fd = getattr(os, "supports_fd", ()) or ()
    follow = getattr(os, "supports_follow_symlinks", ()) or ()
    return (
        all(_member(functions[name], dir_fd)
            for name in ("open", "stat", "readlink", "link", "unlink"))
        and _member(functions["scandir"], fd)
        and all(_member(functions[name], follow) for name in ("stat", "link"))
        and callable(getattr(os, "fstat", None))
        and callable(getattr(os, "fsync", None))
        and bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and pwd is not None
        and callable(getattr(pwd, "getpwuid", None))
        and callable(getattr(os, "getuid", None))
    )


def _parser():
    parser = SafeParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--show-paths", action="store_true")
    parser.add_argument("--output")
    return parser


PARSER = _parser()


def main(argv=None):
    try:
        PARSER.parse_args(argv)
        if not _capable():
            raise OperationalError("SAFE_IO_UNAVAILABLE")
        raise OperationalError("AUDIT_INCOMPLETE")
    except OperationalError as error:
        sys.stderr.write(f"{error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

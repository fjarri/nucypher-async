import importlib.metadata
import subprocess
from collections.abc import Sequence
from pathlib import Path

from attrs import frozen


def _run_in_project_dir(cmd: Sequence[str]) -> str:
    cwd = Path(__file__).parent
    results = subprocess.run(cmd, capture_output=True, cwd=cwd, check=True)  # noqa: S603
    return results.stdout.strip().decode()


@frozen
class FileDiff:
    path: str
    added: int
    removed: int


@frozen
class CodeInfo:
    version: str
    release: bool
    git_revision: str | None
    diff: list[FileDiff]

    @classmethod
    def collect(cls) -> "CodeInfo":
        version = importlib.metadata.version("nucypher-async")
        revision = git_revision()

        if revision:
            tag = git_tag()
            release = tag is not None and "v" + version == tag
            diff = git_diff()
        else:
            release = True
            diff = []

        return cls(version=version, release=release, git_revision=revision, diff=diff)


def git_revision() -> str | None:
    try:
        revision = _run_in_project_dir(["git", "rev-parse", "HEAD"])
    except OSError:
        return None
    return revision or None


def git_tag() -> str | None:
    try:
        tag = _run_in_project_dir(["git", "tag", "--points-at", "HEAD"])
    except OSError:
        return None
    return tag or None


def git_diff() -> list[FileDiff]:
    try:
        diff_str = _run_in_project_dir(["git", "diff", "--numstat"])
    except OSError:
        diff_str = None

    if diff_str:
        diff = []
        file_strs = diff_str.split("\n")
        for file_str in file_strs:
            added, removed, path = file_str.split("\t")
            diff.append(FileDiff(path=path, added=int(added), removed=int(removed)))
        return diff

    return []

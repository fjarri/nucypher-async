import os
from pathlib import Path
import subprocess
from typing import Optional, List, Sequence

from attrs import frozen
import pkg_resources


def _run_in_project_dir(cmd: Sequence[str]) -> bytes:
    cwd = Path(__file__).parent
    stdout_data, _stderr_data = subprocess.Popen(cmd, stdout=subprocess.PIPE, cwd=cwd).communicate()
    return stdout_data


@frozen
class FileDiff:
    path: str
    added: int
    removed: int


@frozen
class CodeInfo:
    version: str
    release: bool
    git_revision: Optional[str]
    diff: List[FileDiff]

    @classmethod
    def collect(cls) -> "CodeInfo":
        version = pkg_resources.get_distribution("nucypher-async").version
        revision = git_revision()

        if revision:
            tag = git_tag()
            release = tag is not None and "v" + version == tag
            diff = git_diff()
        else:
            release = True
            diff = []

        return cls(version=version, release=release, git_revision=revision, diff=diff)


def git_revision() -> Optional[str]:
    try:
        out = _run_in_project_dir(["git", "rev-parse", "HEAD"])
    except OSError:
        return None
    revision = out.strip().decode()
    return revision or None


def git_tag() -> Optional[str]:
    try:
        out = _run_in_project_dir(["git", "tag", "--points-at", "HEAD"])
    except OSError:
        return None
    tag = out.strip().decode()
    return tag or None


def git_diff() -> List[FileDiff]:
    try:
        out = _run_in_project_dir(["git", "diff", "--numstat"])
        diff_str = out.strip().decode()
    except OSError:
        diff_str = None

    if diff_str:
        diff = []
        file_strs = diff_str.split("\n")
        for file_str in file_strs:
            added, removed, path = file_str.split("\t")
            diff.append(FileDiff(path=path, added=int(added), removed=int(removed)))
        return diff
    else:
        return []

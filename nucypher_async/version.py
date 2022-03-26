import os
from pathlib import Path
import subprocess
from typing import Optional, List

from attrs import define
import pkg_resources


def _run_in_project_dir(cmd):
    cwd = Path(__file__).parent
    out = subprocess.Popen(cmd, stdout=subprocess.PIPE, cwd=cwd).communicate()[0]
    return out


@define
class FileDiff:
    path: str
    added: int
    removed: int


@define
class CodeInfo:
    version: str
    release: bool
    git_revision: Optional[str]
    diff: List[FileDiff]

    @classmethod
    def collect(cls):
        version = pkg_resources.get_distribution('nucypher-async').version
        revision = git_revision()

        if revision:
            tag = git_tag()
            release = tag and 'v' + tag == version
            diff = git_diff()
        else:
            release = True
            diff = []

        return cls(version=version, release=release, git_revision=revision, diff=diff)


def git_revision():
    try:
        out = _run_in_project_dir(['git', 'rev-parse', 'HEAD'])
    except OSError:
        return None
    revision = out.strip().decode()
    return revision or None


def git_tag():
    try:
        out = _run_in_project_dir(['git', 'tag', '--points-at', 'HEAD'])
    except OSError:
        return None
    tag = out.strip().decode()
    return tag or None


def git_diff():
    try:
        out = _run_in_project_dir(['git', 'diff', '--numstat'])
        diff_str = out.strip().decode()
    except OSError:
        diff_str = None

    if diff_str:
        diff = []
        file_strs = diff_str.split('\n')
        for file_str in file_strs:
            added, removed, path = file_str.split('\t')
            diff.append(FileDiff(path=path, added=int(added), removed=int(removed)))
        return diff
    else:
        return None

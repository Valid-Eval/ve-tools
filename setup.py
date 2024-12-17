#!/usr/bin/env python

from pathlib import Path
from setuptools import setup, find_packages

# This is where you add any fancy path resolution to the local lib:
local_path: str = (Path(__file__).parent / "openforge").as_uri()

with open("requirements.txt") as f:
    required = f.read().splitlines()

setup(
    install_requires=required,
    packages=find_packages(include=['vetools', 'vetools.*']),
    scripts=[
        "bin/kubectl-ve-queues",
        "bin/kubectl-ve-queue",
        "bin/kubectl-ve-console"
    ],
)

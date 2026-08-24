"""
One interpreter version, asserted in every place that names it.

requirements.txt is a `uv pip compile --python-version 3.12` output: a complete, pinned
set resolved for exactly that interpreter. The Dockerfile built on 3.11 anyway, and the
CI workflow audited on 3.11, so three places claimed a different answer to "what does
this run on" and nothing compared them. That is the quiet kind of drift — it costs
nothing until a pin resolves to a wheel the deployment's Python cannot install, and then
it fails in the one environment nobody tests.

The version lives in exactly one place here. Changing it means recompiling
requirements.txt for the new interpreter (see requirements-dev.txt), not editing this
constant until the suite goes green.
"""

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

PYTHON_VERSION = "3.12"


def test_requirements_are_compiled_for_the_supported_version():
    """The lockfile header records the interpreter uv resolved against. It is generated
    output, so this is the authoritative statement of what the pins mean."""
    header = (REPO_ROOT / "requirements.txt").read_text().split("\n")[:5]
    compile_command = "\n".join(header)

    match = re.search(r"--python-version (\d+\.\d+)", compile_command)
    assert match, (
        "requirements.txt no longer records its --python-version. It must stay a "
        "`uv pip compile --universal --python-version X.Y` output — see requirements-dev.txt "
        "for why --universal is not optional."
    )
    assert match.group(1) == PYTHON_VERSION, (
        f"requirements.txt is compiled for {match.group(1)}, but the deployment runs "
        f"{PYTHON_VERSION}. Recompile it, or change PYTHON_VERSION here and every other "
        "place this test checks — together, in one commit."
    )


def test_docker_stages_agree_with_each_other_and_with_the_lockfile():
    """Both stages must name the same minor version, not just the supported one.

    The builder installs to /install/lib/pythonX.Y/site-packages and the runtime stage
    copies that tree wholesale to /usr/local. If the two minor versions differ, the image
    builds and pushes cleanly and then fails on the first import at container start.
    """
    dockerfile = (REPO_ROOT / "Dockerfile").read_text()
    versions = re.findall(r"^FROM python:(\d+\.\d+)-slim", dockerfile, re.MULTILINE)

    assert versions, "Dockerfile has no `FROM python:X.Y-slim` stage — update this test."
    assert len(set(versions)) == 1, (
        f"Dockerfile builds on Python {sorted(set(versions))}. The runtime stage copies the "
        "builder's site-packages into /usr/local, so mismatched minor versions produce an "
        "image whose every import fails at startup."
    )
    assert versions[0] == PYTHON_VERSION


@pytest.mark.parametrize(
    "workflow", sorted(p.name for p in (REPO_ROOT / ".forgejo" / "workflows").glob("*.yml"))
)
def test_ci_workflows_use_the_supported_version(workflow):
    """A green CI run on an interpreter the deployment does not use is a green tick for a
    question nobody asked."""
    content = (REPO_ROOT / ".forgejo" / "workflows" / workflow).read_text()
    pinned = re.findall(r"^\s*python-version:\s*[\"']?(\d+\.\d+)[\"']?", content, re.MULTILINE)

    for version in pinned:
        assert version == PYTHON_VERSION, (
            f"{workflow} sets up Python {version}; requirements.txt is compiled for "
            f"{PYTHON_VERSION} and the Docker image runs it."
        )


def test_installer_provisions_the_supported_version():
    """install.sh is how the reference deployment gets its interpreter, so it is the one
    place where a wrong version is not a test failure but a broken server."""
    installer = (REPO_ROOT / "install.sh").read_text()
    versions = set(re.findall(r"python(\d+\.\d+)", installer))

    assert versions, "install.sh no longer pins a python3.X package — update this test."
    assert versions == {PYTHON_VERSION}, (
        f"install.sh provisions Python {sorted(versions)}, but requirements.txt is compiled "
        f"for {PYTHON_VERSION}."
    )

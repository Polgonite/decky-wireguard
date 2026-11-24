"""Select and bump plugin versions for stable releases and development builds.

package.json holds the plugin version. A stable release must be exactly one patch,
minor or major step above the latest stable tag (vMAJOR.MINOR.PATCH). Development
builds append a unique suffix to the version that will be released next.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KINDS = ("patch", "minor", "major")
PLAIN = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
STABLE_TAG = re.compile(r"(?:refs/tags/)?v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")

Version = tuple[int, int, int]


class VersionError(Exception):
    pass


def parse(version: str) -> Version | None:
    match = PLAIN.fullmatch(version)
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def text(version: Version) -> str:
    return ".".join(map(str, version))


def latest_stable(refs) -> Version | None:
    versions = [
        (int(match[1]), int(match[2]), int(match[3]))
        for ref in refs
        if (match := STABLE_TAG.fullmatch(ref.strip()))
    ]
    return max(versions, default=None)


def bump(version: Version, kind: str) -> Version:
    major, minor, patch = version
    return {"patch": (major, minor, patch + 1), "minor": (major, minor + 1, 0), "major": (major + 1, 0, 0)}[kind]


def step(latest: Version, version: Version) -> str | None:
    return next((kind for kind in KINDS if bump(latest, kind) == version), None)


def _invalid_step(version: Version, latest: Version) -> VersionError:
    problem = "is already released or older than" if version <= latest else "skips versions after"
    allowed = ", ".join(f"{text(bump(latest, kind))} ({kind})" for kind in KINDS)
    return VersionError(
        f"Version {text(version)} {problem} the latest stable release v{text(latest)}. "
        f"Run `npm run bump -- patch|minor|major` on dev. Valid next versions: {allowed}."
    )


def select(channel: str, package_version: str, refs) -> dict[str, str]:
    """Return the release version, kind and previous stable tag for a channel."""
    latest = latest_stable(refs)
    base_text = re.split(r"[-+]", package_version, maxsplit=1)[0]
    base = parse(base_text)
    if base is None:
        raise VersionError(f"package.json version '{package_version}' must start with a plain MAJOR.MINOR.PATCH version.")

    if channel == "stable" and package_version != base_text:
        raise VersionError(f"Stable releases need a plain MAJOR.MINOR.PATCH version in package.json, not '{package_version}'.")
    if latest is None:
        kind = "initial"
    elif channel == "development" and base == latest:
        # The version on dev was just released; build towards the next patch until it is bumped.
        base, kind = bump(latest, "patch"), "patch"
    elif not (kind := step(latest, base)):
        raise _invalid_step(base, latest)
    return {
        "version": text(base),
        "channel": channel,
        "kind": kind,
        "previous": f"v{text(latest)}" if latest else "",
    }


def development_version(base: str, run_id: str, attempt: str, sha: str) -> str:
    return f"{base}-dev.{run_id}.{attempt}.sha{sha[:7]}"


def package_version() -> str:
    return json.loads((ROOT / "package.json").read_text())["version"]


def remote_tags(remote: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", remote, "v*"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    return [line.split("\t", 1)[1] for line in result.stdout.splitlines() if "\t" in line]


def describe(release: dict[str, str]) -> str:
    if release["channel"] == "development":
        target = "first stable" if release["kind"] == "initial" else f"next {release['kind']}"
        return f"Development build towards the {target} release {release['version']}."
    if release["kind"] == "initial":
        return f"Stable release v{release['version']} is the first stable release."
    return f"Stable release v{release['version']} is a {release['kind']} release after {release['previous']}."


def run_select(args) -> None:
    release = select(args.channel, package_version(), sys.stdin)
    message = describe(release)
    if release["channel"] == "development":
        release["version"] = development_version(release["version"], args.run_id, args.attempt, args.sha)
    lines = [f"{key}={value}" for key, value in release.items()]
    if args.output:
        with open(args.output, "a") as output:
            output.write("".join(f"{line}\n" for line in lines))
    else:
        print("\n".join(lines))
    print(f"::notice::{message}" if os.environ.get("GITHUB_ACTIONS") == "true" else message)


def run_bump(args) -> None:
    current = package_version()
    latest = latest_stable(remote_tags(args.remote))
    start = latest or parse(re.split(r"[-+]", current, maxsplit=1)[0])
    if start is None:
        raise VersionError(f"package.json version '{current}' must start with a plain MAJOR.MINOR.PATCH version.")
    new = bump(start, args.kind)
    version = text(new)
    subprocess.run(
        ["npm", "version", version, "--no-git-tag-version", "--ignore-scripts", "--allow-same-version"],
        cwd=ROOT, check=True, stdout=subprocess.DEVNULL,
    )
    after = f"after v{text(latest)}" if latest else "(no stable release yet)"
    print(f"package.json: {current} -> {version}, the next {args.kind} release {after}.")
    current_base = parse(re.split(r"[-+]", current, maxsplit=1)[0])
    if current_base and current_base > new:
        print(
            f"Warning: {version} is lower than {current}. Installed development builds of {current} "
            "will not update to it, because the updater never downgrades.",
            file=sys.stderr,
        )
    print("Commit package.json and package-lock.json on dev, then open a pull request into main.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    select_parser = commands.add_parser("select", help="Select the release version from tag refs on stdin.")
    select_parser.add_argument("--channel", choices=("stable", "development"), required=True)
    select_parser.add_argument("--run-id", default="0")
    select_parser.add_argument("--attempt", default="0")
    select_parser.add_argument("--sha", default="0000000")
    select_parser.add_argument("--output", help="Append key=value lines to this file, such as $GITHUB_OUTPUT.")

    bump_parser = commands.add_parser("bump", help="Set package.json to the next stable version.")
    bump_parser.add_argument("kind", choices=KINDS)
    bump_parser.add_argument("--remote", default="origin")

    args = parser.parse_args(argv)
    try:
        if args.command == "select":
            run_select(args)
        else:
            run_bump(args)
    except VersionError as error:
        print(f"::error::{error}" if os.environ.get("GITHUB_ACTIONS") == "true" else f"Error: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

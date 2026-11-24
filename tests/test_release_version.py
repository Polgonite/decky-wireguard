import unittest

from tools.release_version import VersionError, development_version, latest_stable, select


TAGS = [
    "refs/tags/v0.9.1",
    "refs/tags/v0.10.0",
    "refs/tags/v0.11.0-dev.4.1.shaabcdef0",
    "refs/tags/v1.0",
    "refs/tags/release-2.0.0",
]


class LatestStableTests(unittest.TestCase):
    def test_highest_plain_version_tag_wins_numerically(self):
        self.assertEqual(latest_stable(TAGS), (0, 10, 0))
        self.assertEqual(latest_stable(["v0.2.0\n", "v0.1.9"]), (0, 2, 0))
        self.assertIsNone(latest_stable(["refs/tags/v0.1.0-dev.1.1.sha1234567"]))


class StableSelectionTests(unittest.TestCase):
    def test_first_release_accepts_any_plain_version(self):
        self.assertEqual(
            select("stable", "0.1.0", []),
            {"version": "0.1.0", "channel": "stable", "kind": "initial", "previous": ""},
        )

    def test_exactly_one_step_above_latest_stable(self):
        for version, kind in (("0.10.1", "patch"), ("0.11.0", "minor"), ("1.0.0", "major")):
            with self.subTest(version=version):
                release = select("stable", version, TAGS)
                self.assertEqual((release["kind"], release["previous"]), (kind, "v0.10.0"))

    def test_released_older_skipped_or_suffixed_versions_are_rejected(self):
        for version, message in (
            ("0.10.0", "already released or older"),
            ("0.9.2", "already released or older"),
            ("0.10.2", "skips versions"),
            ("0.12.0", "skips versions"),
            ("0.11.0-rc.1", "plain MAJOR.MINOR.PATCH"),
            ("v0.11.0", "must start with"),
        ):
            with self.subTest(version=version), self.assertRaisesRegex(VersionError, message):
                select("stable", version, TAGS)


class DevelopmentSelectionTests(unittest.TestCase):
    def test_unreleased_next_version_is_kept(self):
        release = select("development", "0.11.0", TAGS)
        self.assertEqual((release["version"], release["kind"]), ("0.11.0", "minor"))
        self.assertEqual(select("development", "0.11.0-local", TAGS)["version"], "0.11.0")
        self.assertEqual(select("development", "0.1.0", [])["kind"], "initial")

    def test_released_version_builds_towards_next_patch(self):
        release = select("development", "0.10.0", TAGS)
        self.assertEqual((release["version"], release["kind"]), ("0.10.1", "patch"))

    def test_older_or_skipped_versions_fail_early(self):
        for version in ("0.9.2", "0.10.2", "2.0.0"):
            with self.subTest(version=version), self.assertRaises(VersionError):
                select("development", version, TAGS)

    def test_development_version_sorts_below_its_release(self):
        self.assertEqual(
            development_version("0.11.0", "123", "2", "0123456789abcdef"),
            "0.11.0-dev.123.2.sha0123456",
        )

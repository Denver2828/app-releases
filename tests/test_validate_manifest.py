import copy
import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "validate_manifest.py"
SPEC = importlib.util.spec_from_file_location("validate_manifest", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ZERO = "0" * 64


def valid_manifest():
    return {
        "schemaVersion": 1,
        "appId": "you2be-music",
        "channel": "stable",
        "packageName": "com.you2be.music",
        "versionCode": 153,
        "versionName": "1.4.1",
        "publishedAt": "2026-09-20T12:00:00Z",
        "source": {"url": "https://example.invalid/source.tar.gz", "sha256": ZERO},
        "artifacts": [{
            "type": "apk", "abi": "universal", "url": "https://example.invalid/app.apk",
            "size": 10, "sha256": ZERO, "packageName": "com.you2be.music",
            "versionCode": 153, "certificateSha256": ZERO,
        }],
    }


class ManifestValidationTest(unittest.TestCase):
    def test_accepts_full_apk_manifest(self):
        self.assertEqual([], MODULE.validate(valid_manifest()))

    def test_rejects_cross_app_package(self):
        data = valid_manifest()
        data["packageName"] = "com.you2be.musictv"
        self.assertIn("packageName does not belong to appId", MODULE.validate(data))

    def test_patch_requires_full_fallback(self):
        data = valid_manifest()
        data["artifacts"] = [{
            "type": "patch", "abi": "arm64-v8a", "fromVersionCode": 152,
            "patchAlgorithm": "bsdiff", "url": "https://example.invalid/app.patch",
            "size": 5, "sha256": ZERO, "packageName": "com.you2be.music",
            "versionCode": 153, "certificateSha256": ZERO,
        }]
        self.assertTrue(any("fallback" in error for error in MODULE.validate(data)))

    def test_patch_and_matching_apk_are_valid(self):
        data = valid_manifest()
        apk = copy.deepcopy(data["artifacts"][0])
        apk["abi"] = "arm64-v8a"
        patch = copy.deepcopy(apk)
        patch.update(type="patch", fromVersionCode=152, patchAlgorithm="bsdiff", url="https://example.invalid/app.patch")
        data["artifacts"] = [apk, patch]
        self.assertEqual([], MODULE.validate(data))

    def test_rejects_certificate_digest_with_wrong_length(self):
        data = valid_manifest()
        data["artifacts"][0]["certificateSha256"] = "abc"
        self.assertTrue(any("certificateSha256" in error for error in MODULE.validate(data)))


if __name__ == "__main__":
    unittest.main()

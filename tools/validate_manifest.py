#!/usr/bin/env python3
import argparse
import hashlib
import json
import pathlib
import sys
import urllib.parse

APP_PACKAGES = {
    "you2be-music": {"com.you2be.music"},
    "you2be-music-tv": {"com.you2be.music"},
    "you2be-video-tv": {
        "com.you2be.videotv.beta",
        "com.you2be.videotv.stable",
        "com.you2be.videotv.fdroid",
    },
}
ABIS = {"universal", "arm64-v8a", "armeabi-v7a", "x86", "x86_64"}
SHA256_LENGTH = 64


def _require_https(value, field, errors):
    parsed = urllib.parse.urlparse(value if isinstance(value, str) else "")
    if parsed.scheme != "https" or not parsed.netloc:
        errors.append(f"{field} must be an absolute HTTPS URL")


def _require_sha256(value, field, errors):
    if not isinstance(value, str) or len(value) != SHA256_LENGTH:
        errors.append(f"{field} must be a lowercase SHA-256 digest")
        return
    try:
        int(value, 16)
    except ValueError:
        errors.append(f"{field} must be a lowercase SHA-256 digest")
        return
    if value != value.lower():
        errors.append(f"{field} must be a lowercase SHA-256 digest")


def validate(data):
    errors = []
    required = ("schemaVersion", "appId", "channel", "packageName", "versionCode", "versionName", "publishedAt", "source", "artifacts")
    for field in required:
        if field not in data:
            errors.append(f"missing {field}")
    if errors:
        return errors

    app_id = data["appId"]
    package_name = data["packageName"]
    if data["schemaVersion"] != 1:
        errors.append("schemaVersion must be 1")
    if app_id not in APP_PACKAGES:
        errors.append("unknown appId")
    elif package_name not in APP_PACKAGES[app_id]:
        errors.append("packageName does not belong to appId")
    if data["channel"] not in {"stable", "beta"}:
        errors.append("channel must be stable or beta")
    if not isinstance(data["versionCode"], int) or data["versionCode"] < 1:
        errors.append("versionCode must be a positive integer")

    source = data["source"]
    if not isinstance(source, dict):
        errors.append("source must be an object")
    else:
        _require_https(source.get("url"), "source.url", errors)
        _require_sha256(source.get("sha256"), "source.sha256", errors)

    artifacts = data["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("artifacts must be a non-empty array")
        return errors

    full_apk_keys = set()
    patch_keys = []
    for index, artifact in enumerate(artifacts):
        field = f"artifacts[{index}]"
        if not isinstance(artifact, dict):
            errors.append(f"{field} must be an object")
            continue
        artifact_type = artifact.get("type")
        abi = artifact.get("abi")
        if artifact_type not in {"apk", "patch"}:
            errors.append(f"{field}.type must be apk or patch")
        if abi not in ABIS:
            errors.append(f"{field}.abi is unsupported")
        if artifact.get("packageName") != package_name:
            errors.append(f"{field}.packageName differs from manifest")
        if artifact.get("versionCode") != data["versionCode"]:
            errors.append(f"{field}.versionCode differs from manifest")
        if not isinstance(artifact.get("size"), int) or artifact["size"] < 1:
            errors.append(f"{field}.size must be positive")
        _require_https(artifact.get("url"), f"{field}.url", errors)
        _require_sha256(artifact.get("sha256"), f"{field}.sha256", errors)
        _require_sha256(artifact.get("certificateSha256"), f"{field}.certificateSha256", errors)
        if artifact_type == "apk":
            full_apk_keys.add(abi)
            if "fromVersionCode" in artifact or "patchAlgorithm" in artifact:
                errors.append(f"{field} APK must not declare patch fields")
        elif artifact_type == "patch":
            if not isinstance(artifact.get("fromVersionCode"), int) or artifact["fromVersionCode"] < 1:
                errors.append(f"{field}.fromVersionCode must be positive")
            if artifact.get("patchAlgorithm") != "bsdiff":
                errors.append(f"{field}.patchAlgorithm must be bsdiff")
            patch_keys.append((field, abi))

    if "universal" not in full_apk_keys:
        for field, abi in patch_keys:
            if abi not in full_apk_keys:
                errors.append(f"{field} has no matching full APK fallback")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("--artifact-root", type=pathlib.Path)
    args = parser.parse_args(argv)
    data = json.loads(args.manifest.read_text(encoding="utf-8"))
    errors = validate(data)
    if args.artifact_root:
        for index, artifact in enumerate(data.get("artifacts", [])):
            filename = pathlib.Path(urllib.parse.urlparse(artifact.get("url", "")).path).name
            local = args.artifact_root / filename
            if not local.is_file():
                errors.append(f"artifacts[{index}] local file missing: {filename}")
                continue
            digest = hashlib.sha256(local.read_bytes()).hexdigest()
            if digest != artifact.get("sha256"):
                errors.append(f"artifacts[{index}] local SHA-256 mismatch")
            if local.stat().st_size != artifact.get("size"):
                errors.append(f"artifacts[{index}] local size mismatch")
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("manifest valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

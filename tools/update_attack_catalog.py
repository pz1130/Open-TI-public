"""从 MITRE ATT&CK Enterprise STIX 2.1 Bundle 生成平台使用的精简目录。

先下载 README 所列的版本化 enterprise-attack JSON，再传入本地路径；不在运行时联网。
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

IDS = ("T1566", "T1583.001", "T1585.001")
SOURCE = "https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack-19.2.json"
SOURCE_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
OUTPUT = Path(__file__).resolve().parents[1] / "src/opti/core/attack_catalog.json"


def build(source: Path) -> dict[str, object]:
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SOURCE_SHA256:
        raise ValueError("STIX bundle does not match the pinned MITRE version")
    bundle = json.loads(raw)
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("expected a STIX bundle")
    patterns = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id") in IDS:
                tid = ref["external_id"]
                if (
                    obj.get("spec_version") != "2.1"
                    or obj.get("revoked")
                    or obj.get("x_mitre_deprecated")
                    or tid in patterns
                ):
                    raise ValueError(f"inactive, non-STIX-2.1, or duplicate technique: {tid}")
                tactics = sorted(
                    {
                        phase["phase_name"]
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name") == "mitre-attack"
                    }
                )
                if not tactics or not str(ref.get("url", "")).startswith(
                    "https://attack.mitre.org/techniques/"
                ):
                    raise ValueError(f"missing tactic or official URL: {tid}")
                patterns[tid] = {
                    "id": tid,
                    "stix_id": obj["id"],
                    "name": obj["name"],
                    "tactics": tactics,
                    "url": ref["url"] + "/",
                    "modified": obj["modified"],
                }
    if set(patterns) != set(IDS):
        raise ValueError(f"missing ATT&CK techniques: {set(IDS) - set(patterns)}")
    return {
        "source": SOURCE,
        "source_sha256": digest,
        "techniques": [patterns[tid] for tid in IDS],
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tools/update_attack_catalog.py enterprise-attack-19.2.json")
    OUTPUT.write_text(json.dumps(build(Path(sys.argv[1])), ensure_ascii=False, indent=2) + "\n")

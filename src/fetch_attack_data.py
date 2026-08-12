"""
Ingestion: pull MITRE ATT&CK Enterprise techniques (ID, name, description, tactics)
and store them locally as JSON/CSV so we never need to re-fetch on every run.

Source: the official ATT&CK STIX 2.1 bundle, fetched via mitreattack-python's
MitreAttackData helper (which itself wraps the STIX2 TAXII/GitHub bundle).
"""

import json
import os
import urllib.request

import pandas as pd
from mitreattack.stix20 import MitreAttackData

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
STIX_PATH = os.path.join(DATA_DIR, "enterprise-attack.json")
JSON_OUT = os.path.join(DATA_DIR, "techniques.json")
CSV_OUT = os.path.join(DATA_DIR, "techniques.csv")

# Some techniques (e.g. PowerShell, Phishing) have 100s of documented
# procedure examples; capping keeps the index balanced instead of letting a
# few heavily-cited techniques drown everything else out.
MAX_PROCEDURE_EXAMPLES = 25


def download_stix_bundle(force: bool = False) -> str:
    """Download the raw STIX bundle once and cache it locally."""
    if os.path.exists(STIX_PATH) and not force:
        print(f"STIX bundle already cached at {STIX_PATH}")
        return STIX_PATH

    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"Downloading ATT&CK Enterprise STIX bundle from {STIX_URL} ...")
    urllib.request.urlretrieve(STIX_URL, STIX_PATH)
    print(f"Saved to {STIX_PATH}")
    return STIX_PATH


def extract_procedure_examples(attack_data: MitreAttackData, tech: dict) -> list[str]:
    """Real-world 'Group/Software used T1234 to...' descriptions for a technique.

    These use concrete, incident-report-style language (often naming specific
    CVEs and products) that's much closer to how real-world queries are
    phrased than the technique's own abstract definition text — valuable
    extra grounding for semantic matching.
    """
    examples = attack_data.get_procedure_examples_by_technique(tech["id"])
    texts = [
        (ex.get("description", "") or "").replace("\n", " ").strip()
        for ex in examples
    ]
    texts = [t for t in texts if t]
    return texts[:MAX_PROCEDURE_EXAMPLES]


def extract_techniques(stix_path: str) -> list[dict]:
    """Use mitreattack-python to parse the STIX bundle into flat technique records."""
    attack_data = MitreAttackData(stix_path)
    techniques = attack_data.get_techniques(remove_revoked_deprecated=True)

    records = []
    for tech in techniques:
        # external_references[0] is always the ATT&CK source with the technique ID
        attack_id = None
        for ref in tech.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                break
        if not attack_id:
            continue

        tactics = sorted(
            {phase["phase_name"] for phase in tech.get("kill_chain_phases", [])}
        )
        is_subtechnique = tech.get("x_mitre_is_subtechnique", False)

        records.append(
            {
                "technique_id": attack_id,
                "name": tech.get("name", ""),
                "description": (tech.get("description", "") or "").replace("\n", " ").strip(),
                "tactics": tactics,
                "is_subtechnique": is_subtechnique,
                "platforms": tech.get("x_mitre_platforms", []),
                "procedure_examples": extract_procedure_examples(attack_data, tech),
            }
        )

    records.sort(key=lambda r: r["technique_id"])
    return records


def save_records(records: list[dict]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)

    with open(JSON_OUT, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    print(f"Wrote {len(records)} techniques to {JSON_OUT}")

    df = pd.DataFrame(records)
    df["tactics"] = df["tactics"].apply(lambda t: ", ".join(t))
    df["platforms"] = df["platforms"].apply(lambda p: ", ".join(p))
    df["procedure_examples"] = df["procedure_examples"].apply(lambda p: " | ".join(p))
    df.to_csv(CSV_OUT, index=False)
    print(f"Wrote {len(records)} techniques to {CSV_OUT}")


def main():
    stix_path = download_stix_bundle()
    records = extract_techniques(stix_path)
    save_records(records)


if __name__ == "__main__":
    main()

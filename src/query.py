"""
Query/matching: embed a free-text description (CVE summary, incident report,
attacker behavior) with the same sentence-transformer model used to embed the
ATT&CK techniques, then rank all techniques by cosine similarity.

Usage:
    python src/query.py "Attacker used PowerShell to download and execute a
    remote payload, then dumped LSASS memory to harvest credentials."
"""

import argparse
import json
import os

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
TECHNIQUES_JSON = os.path.join(DATA_DIR, "techniques.json")
EMBEDDINGS_PATH = os.path.join(DATA_DIR, "embeddings.npy")
IDS_PATH = os.path.join(DATA_DIR, "technique_ids.json")

MODEL_NAME = "all-MiniLM-L6-v2"

_model = None


def get_model() -> SentenceTransformer:
    """Lazily load and cache the sentence-transformer model for reuse across calls."""
    global _model
    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def load_index():
    """Load cached technique embeddings + metadata. Raises if not yet built."""
    for path in (EMBEDDINGS_PATH, IDS_PATH, TECHNIQUES_JSON):
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{path} not found. Run src/fetch_attack_data.py then "
                "src/build_embeddings.py first."
            )

    embeddings = np.load(EMBEDDINGS_PATH)
    with open(IDS_PATH, "r", encoding="utf-8") as f:
        ids = json.load(f)
    with open(TECHNIQUES_JSON, "r", encoding="utf-8") as f:
        techniques = {t["technique_id"]: t for t in json.load(f)}

    return embeddings, ids, techniques


def top_matches(text: str, top_k: int = 5, model=None, embeddings=None, ids=None, techniques=None):
    """Return the top_k ATT&CK techniques most semantically similar to `text`.

    The index is chunk-level (one row per technique sentence, so `ids` has
    repeats): a technique's score is the max similarity over its chunks,
    which avoids one broad match getting diluted by its technique's other,
    less-relevant sentences.
    """
    if model is None:
        model = get_model()
    if embeddings is None or ids is None or techniques is None:
        embeddings, ids, techniques = load_index()

    query_vec = model.encode([text], convert_to_numpy=True, normalize_embeddings=True)
    sims = cosine_similarity(query_vec, embeddings)[0]

    best_score: dict[str, float] = {}
    for idx, tech_id in enumerate(ids):
        score = sims[idx]
        if tech_id not in best_score or score > best_score[tech_id]:
            best_score[tech_id] = score

    ranked = sorted(best_score.items(), key=lambda kv: -kv[1])[:top_k]
    results = []
    for tech_id, score in ranked:
        tech = techniques[tech_id]
        results.append(
            {
                "technique_id": tech_id,
                "name": tech["name"],
                "tactics": tech.get("tactics", []),
                "score": float(score),
            }
        )
    return results


def main():
    parser = argparse.ArgumentParser(description="Map free-text to MITRE ATT&CK techniques")
    parser.add_argument("text", help="Free-text threat/incident/CVE description")
    parser.add_argument("--top-k", type=int, default=5, help="Number of matches to return")
    args = parser.parse_args()

    results = top_matches(args.text, top_k=args.top_k)

    print(f"\nQuery: {args.text}\n")
    print(f"Top {len(results)} ATT&CK technique matches:\n")
    for rank, r in enumerate(results, start=1):
        tactics = ", ".join(r["tactics"]) if r["tactics"] else "-"
        print(f"{rank}. [{r['technique_id']}] {r['name']}  (score={r['score']:.4f})")
        print(f"   tactics: {tactics}")


if __name__ == "__main__":
    main()

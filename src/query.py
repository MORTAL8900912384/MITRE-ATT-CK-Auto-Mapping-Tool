"""
Query/matching: embed a free-text description (CVE summary, incident report,
attacker behavior) with the same sentence-transformer model used to embed the
ATT&CK techniques, then rank techniques by SBERT cosine similarity.

An optional second stage (rerank=True) widens the candidate pool with BM25
lexical matches and rescoes it with a cross-encoder for a sharper #1 answer —
but it's off by default. On the validation set, every off-the-shelf
cross-encoder tried (ms-marco-MiniLM-L-6-v2, stsb-distilroberta-base,
qnli-distilroberta-base) made both top-1 and top-5 noticeably *worse* than
plain semantic ranking, apparently because none of them are trained on
anything resembling this domain (short incident text vs. formal ATT&CK
technique/procedure text). The code is kept because it's a reasonable
approach that would likely pay off with a properly fine-tuned or
better-matched cross-encoder — see README for the numbers and reasoning.

Usage:
    python src/query.py "Attacker used PowerShell to download and execute a
    remote payload, then dumped LSASS memory to harvest credentials."
"""

import argparse
import json
import os
import re

import numpy as np
from rank_bm25 import BM25Okapi
from sentence_transformers import CrossEncoder, SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

from build_embeddings import MODEL_NAME

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
TECHNIQUES_JSON = os.path.join(DATA_DIR, "techniques.json")
EMBEDDINGS_PATH = os.path.join(DATA_DIR, "embeddings.npy")
IDS_PATH = os.path.join(DATA_DIR, "technique_ids.json")
CHUNK_TEXTS_PATH = os.path.join(DATA_DIR, "chunk_texts.json")

CROSS_ENCODER_NAME = "cross-encoder/ms-marco-MiniLM-L-6-v2"

# How many top-scoring techniques from the semantic pass form the main
# candidate pool that gets the (slower) cross-encoder's full attention.
# Must be >= the largest top_k a caller will request.
CANDIDATE_POOL_SIZE = 20

# How many extra techniques BM25 may add to the pool beyond
# CANDIDATE_POOL_SIZE, for techniques with genuine lexical overlap (shared
# exact terms — CVE IDs, product names) that semantic similarity ranked too
# low to make the cut on its own.
#
# BM25 is used this way — widening the pool rather than blending its score
# into the ranking — because blending was tried first and made things worse:
# min-max normalizing BM25 scores per-query stretches even a query's *weak*
# best match up to 1.0, so it gets treated as a strong signal and can
# outweigh a good semantic match. Only ever adding candidates (never
# reordering or displacing what semantic already found) avoids that failure
# mode; on the validation set this lifted top-20 pool recall from 90% to 95%
# (see README) without the blended version's top-5 regression.
LEXICAL_RESCUE_SIZE = 10

TOKEN_RE = re.compile(r"[a-z0-9]+")

_model = None
_cross_encoder = None


def get_model() -> SentenceTransformer:
    """Lazily load and cache the sentence-transformer model for reuse across calls."""
    global _model
    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def get_cross_encoder() -> CrossEncoder:
    """Lazily load and cache the cross-encoder used to rerank shortlisted candidates."""
    global _cross_encoder
    if _cross_encoder is None:
        _cross_encoder = CrossEncoder(CROSS_ENCODER_NAME)
    return _cross_encoder


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


def load_index():
    """Load cached technique embeddings + metadata + a BM25 lexical index.

    Raises if the embedding cache hasn't been built yet.
    """
    for path in (EMBEDDINGS_PATH, IDS_PATH, TECHNIQUES_JSON, CHUNK_TEXTS_PATH):
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
    with open(CHUNK_TEXTS_PATH, "r", encoding="utf-8") as f:
        chunk_texts = json.load(f)

    bm25 = BM25Okapi([tokenize(t) for t in chunk_texts])

    return embeddings, ids, techniques, chunk_texts, bm25


def top_matches(
    text: str,
    top_k: int = 5,
    model=None,
    embeddings=None,
    ids=None,
    techniques=None,
    chunk_texts=None,
    bm25=None,
    cross_encoder=None,
    rerank: bool = False,
):
    """Return the top_k ATT&CK techniques matching `text`.

    Default (rerank=False): pure semantic retrieval. Score every chunk by
    SBERT cosine similarity; a technique's score is its best-matching
    chunk's score (the index is chunk-level, so `ids` has repeats — this
    avoids one broad match getting diluted by a technique's other,
    less-relevant chunks). This is the best-performing, benchmarked
    configuration (see README).

    Opt-in (rerank=True): widens the semantic candidate pool with BM25
    lexical rescues (techniques with genuine exact-term overlap that
    semantic similarity ranked too low to include on its own — this only
    ever adds candidates, never reorders or displaces what semantic already
    found), then rescores every pooled candidate with a cross-encoder over
    (query, best-matching chunk) pairs. Implemented and functional, but
    currently benchmarks *worse* than the default on top-1 and top-5 — kept
    for future experimentation with a better-suited cross-encoder rather
    than shipped as the default. See README for the numbers.
    """
    if model is None:
        model = get_model()
    if embeddings is None or ids is None or techniques is None or chunk_texts is None or bm25 is None:
        embeddings, ids, techniques, chunk_texts, bm25 = load_index()

    query_vec = model.encode([text], convert_to_numpy=True, normalize_embeddings=True)
    semantic_sims = cosine_similarity(query_vec, embeddings)[0]

    sem_best_score: dict[str, float] = {}
    sem_best_chunk: dict[str, int] = {}
    for idx, tech_id in enumerate(ids):
        s = semantic_sims[idx]
        if tech_id not in sem_best_score or s > sem_best_score[tech_id]:
            sem_best_score[tech_id] = s
            sem_best_chunk[tech_id] = idx

    pool_size = max(CANDIDATE_POOL_SIZE, top_k)
    semantic_pool_ids = [tid for tid, _ in sorted(sem_best_score.items(), key=lambda kv: -kv[1])[:pool_size]]

    if not rerank:
        ranked = [(tid, sem_best_score[tid]) for tid in semantic_pool_ids[:top_k]]
    else:
        lexical_sims = np.asarray(bm25.get_scores(tokenize(text)))
        lex_best_score: dict[str, float] = {}
        lex_best_chunk: dict[str, int] = {}
        for idx, tech_id in enumerate(ids):
            l = lexical_sims[idx]
            if tech_id not in lex_best_score or l > lex_best_score[tech_id]:
                lex_best_score[tech_id] = l
                lex_best_chunk[tech_id] = idx

        semantic_pool_set = set(semantic_pool_ids)
        lexical_rescues = [
            tid
            for tid, score in sorted(lex_best_score.items(), key=lambda kv: -kv[1])
            if score > 0 and tid not in semantic_pool_set
        ][:LEXICAL_RESCUE_SIZE]
        lexical_rescue_set = set(lexical_rescues)

        candidate_ids = semantic_pool_ids + lexical_rescues
        representative_chunk = {
            tid: (lex_best_chunk[tid] if tid in lexical_rescue_set else sem_best_chunk[tid])
            for tid in candidate_ids
        }

        if cross_encoder is None:
            cross_encoder = get_cross_encoder()
        pairs = [(text, chunk_texts[representative_chunk[tid]]) for tid in candidate_ids]
        ce_scores = cross_encoder.predict(pairs)
        ranked = sorted(zip(candidate_ids, ce_scores), key=lambda kv: -kv[1])[:top_k]
        ranked = [(tech_id, float(1 / (1 + np.exp(-score)))) for tech_id, score in ranked]

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
    parser.add_argument(
        "--rerank",
        action="store_true",
        help="Enable BM25 lexical-rescue + cross-encoder reranking (experimental; "
        "currently benchmarks worse than the default, see README)",
    )
    args = parser.parse_args()

    results = top_matches(args.text, top_k=args.top_k, rerank=args.rerank)

    print(f"\nQuery: {args.text}\n")
    print(f"Top {len(results)} ATT&CK technique matches:\n")
    for rank, r in enumerate(results, start=1):
        tactics = ", ".join(r["tactics"]) if r["tactics"] else "-"
        print(f"{rank}. [{r['technique_id']}] {r['name']}  (score={r['score']:.4f})")
        print(f"   tactics: {tactics}")


if __name__ == "__main__":
    main()

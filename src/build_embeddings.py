"""
Embedding pipeline: embed every ATT&CK technique using a small CPU-friendly
sentence-transformer (all-MiniLM-L6-v2), and cache the resulting vectors to
disk so they're computed once, not on every query.

Technique descriptions are long (up to ~600 words) and full of citation
markers and markdown links. Embedding the whole thing as a single vector
dilutes the signal: MiniLM truncates at 256 tokens and mean-pools, so a
technique's vector ends up averaged over many tangential details, pulling it
away from its core meaning. Instead we clean the text and split both the
description and any real-world procedure examples into small multi-sentence
chunks (each paired with the technique name for context), embed every chunk
separately, and let query-time matching take the *best*-scoring chunk per
technique. This preserves fine-grained, concrete detail instead of smearing
it into one paragraph-sized average.
"""

import json
import os
import re

import numpy as np
from sentence_transformers import SentenceTransformer

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
TECHNIQUES_JSON = os.path.join(DATA_DIR, "techniques.json")
EMBEDDINGS_OUT = os.path.join(DATA_DIR, "embeddings.npy")
IDS_OUT = os.path.join(DATA_DIR, "technique_ids.json")

MODEL_NAME = "all-MiniLM-L6-v2"

CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")
WHITESPACE_RE = re.compile(r"\s+")
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def load_techniques() -> list[dict]:
    if not os.path.exists(TECHNIQUES_JSON):
        raise FileNotFoundError(
            f"{TECHNIQUES_JSON} not found. Run src/fetch_attack_data.py first."
        )
    with open(TECHNIQUES_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def clean_description(text: str) -> str:
    """Strip citation markers and collapse markdown links to their link text."""
    text = text.replace("\xa0", " ")
    text = CITATION_RE.sub("", text)
    text = MD_LINK_RE.sub(r"\1", text)
    return WHITESPACE_RE.sub(" ", text).strip()


CHUNK_WORD_BUDGET = 60


def group_into_chunks(sentences: list[str], word_budget: int = CHUNK_WORD_BUDGET) -> list[str]:
    """Greedily group sentences into chunks up to a word budget.

    Single sentences are too short: a lone sentence sharing one term with the
    query (e.g. "LDAP") can outscore a correct technique's genuine but less
    lexically-overlapping definition. Grouping a few sentences together keeps
    enough local context to disambiguate while still avoiding the dilution of
    embedding a whole multi-paragraph description as one vector.
    """
    chunks = []
    current: list[str] = []
    current_words = 0
    for sentence in sentences:
        words = len(sentence.split())
        if current and current_words + words > word_budget:
            chunks.append(" ".join(current))
            current, current_words = [], 0
        current.append(sentence)
        current_words += words
    if current:
        chunks.append(" ".join(current))
    return chunks


def technique_to_chunks(tech: dict) -> list[str]:
    """Build name-anchored chunks from a technique's description and, where
    available, its real-world procedure examples.

    Procedure examples ("Group X exploited CVE-Y to...") are written in
    concrete, incident-report language much closer to how real-world queries
    are phrased than ATT&CK's own abstract technique definitions, so they
    give the matcher vocabulary it otherwise wouldn't have.
    """
    cleaned = clean_description(tech["description"])
    sentences = [s.strip() for s in SENTENCE_SPLIT_RE.split(cleaned) if s.strip()]
    if not sentences:
        sentences = [cleaned]
    chunks = group_into_chunks(sentences)

    for example in tech.get("procedure_examples", []):
        cleaned_example = clean_description(example)
        example_sentences = [
            s.strip() for s in SENTENCE_SPLIT_RE.split(cleaned_example) if s.strip()
        ]
        chunks.extend(group_into_chunks(example_sentences or [cleaned_example]))

    return [f"{tech['name']}. {chunk}" for chunk in chunks]


def build_embeddings(force: bool = False) -> None:
    if os.path.exists(EMBEDDINGS_OUT) and os.path.exists(IDS_OUT) and not force:
        print(f"Embeddings already cached at {EMBEDDINGS_OUT}")
        return

    techniques = load_techniques()

    texts = []
    ids = []
    for tech in techniques:
        for chunk in technique_to_chunks(tech):
            texts.append(chunk)
            ids.append(tech["technique_id"])

    print(f"Loading model '{MODEL_NAME}' (first run downloads it, then it's cached)...")
    model = SentenceTransformer(MODEL_NAME)

    print(f"Embedding {len(texts)} sentence chunks from {len(techniques)} techniques...")
    embeddings = model.encode(
        texts, show_progress_bar=True, convert_to_numpy=True, normalize_embeddings=True
    )

    os.makedirs(DATA_DIR, exist_ok=True)
    np.save(EMBEDDINGS_OUT, embeddings)
    with open(IDS_OUT, "w", encoding="utf-8") as f:
        json.dump(ids, f, indent=2)

    print(f"Saved embeddings {embeddings.shape} to {EMBEDDINGS_OUT}")
    print(f"Saved {len(ids)} chunk technique-IDs to {IDS_OUT}")


def main():
    build_embeddings()


if __name__ == "__main__":
    main()

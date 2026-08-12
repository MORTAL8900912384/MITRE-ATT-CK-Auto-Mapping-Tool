# ATT&CK Technique Auto-Mapper (CTI-to-ATT&CK)

Given a free-text threat description — a CVE summary, an incident writeup, an
attacker-behavior sentence — this tool returns the MITRE ATT&CK Enterprise
techniques it most likely maps to, ranked by semantic similarity. It's a
small-scale, offline reproduction of the general idea behind SBERT-based
CTI-to-ATT&CK mapping approaches (e.g. ETRI's published research in this
space): embed technique descriptions and query text with the same
sentence-transformer model, then rank by cosine similarity.

## Problem statement

Analysts triaging a CVE advisory or an incident report have to manually
figure out "which ATT&CK technique(s) does this correspond to?" so it can be
slotted into a threat model, mapped to detections, or compared against known
adversary TTPs. Doing this by hand doesn't scale across the ~200+ Enterprise
techniques/sub-techniques and a constant stream of new CVEs. This tool
automates a first-pass answer: given free text, return the top-5 most
semantically similar ATT&CK techniques.

## Method

1. **Data ingestion** ([src/fetch_attack_data.py](src/fetch_attack_data.py))
   Downloads the official ATT&CK Enterprise STIX 2.1 bundle from the MITRE
   `cti` GitHub repo, parses it with `mitreattack-python`, and flattens every
   technique and sub-technique (ID, name, description, tactics, platforms,
   and up to 25 real-world **procedure examples** — "Group/Software X used
   this technique to..." relationship descriptions, which are often written
   in concrete, incident-report language and name specific CVEs) into
   `data/techniques.json` / `data/techniques.csv`. Cached locally so it is
   only fetched once.

2. **Embedding pipeline** ([src/build_embeddings.py](src/build_embeddings.py))
   Cleans each technique's description and procedure examples (stripping
   `(Citation: ...)` markers and collapsing markdown links to their link
   text), then splits the cleaned text into small multi-sentence chunks
   (~60 words each, name-prefixed for context) rather than embedding the
   whole multi-paragraph description as a single vector. Every chunk is
   embedded with `all-MiniLM-L6-v2` (a small, CPU-friendly
   sentence-transformer) and L2-normalized. The chunk-level embeddings are
   cached to `data/embeddings.npy` alongside a parallel
   `data/technique_ids.json` (one technique ID per chunk row, so IDs repeat)
   so the model only runs once over the corpus, not on every query.

   This chunking exists because a single averaged embedding per technique
   was diluting the signal: `all-MiniLM-L6-v2` truncates at 256 tokens and
   mean-pools, so long, digressive descriptions (e.g. T1190's spends most of
   its length on ESXi/VMware/cloud edge cases) pulled the vector away from
   the technique's core meaning. See [Validation results](#validation-results)
   for the before/after impact.

3. **Query / matching** ([src/query.py](src/query.py))
   Embeds the free-text input with the same model, computes cosine
   similarity (`sklearn.metrics.pairwise.cosine_similarity`) against every
   cached chunk vector, scores each technique by its **best-matching chunk**
   (not an average), and returns the top-5 techniques by that score.

4. **Validation** ([eval/](eval/))
   A hand-built set of 20 examples ([eval/validation_set.json](eval/validation_set.json))
   pairs real CVE descriptions (Log4Shell, EternalBlue, BlueKeep, Zerologon,
   ProxyLogon, MOVEit/Cl0p, Follina, etc., sourced from public CVE write-ups
   and well-documented ATT&CK-CVE mappings) and generic attacker-behavior
   descriptions (LSASS dumping, Kerberoasting, scheduled-task persistence,
   Cobalt Strike beaconing, phishing) with the technique(s) they should map
   to. [eval/evaluate.py](eval/evaluate.py) runs the matcher over the set and
   reports top-1 and top-5 accuracy.

## Setup

```bash
python -m venv venv
venv\Scripts\activate       # PowerShell: venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

```bash
# 1. One-time: fetch ATT&CK data and build the embedding cache
python src/fetch_attack_data.py
python src/build_embeddings.py

# 2. Query
python src/query.py "Attacker used PowerShell to download and execute a remote payload, then dumped LSASS memory to harvest credentials."

# 3. Run the validation set
python eval/evaluate.py

# 4. (Optional) Streamlit demo
streamlit run app.py
```

## Validation results

Run `python eval/evaluate.py` to reproduce. Results as of last run against
the 20-example validation set (`eval/results.json` has full per-example
detail):

| Metric | Score |
|---|---|
| Top-1 accuracy | **30.0%** (6/20) |
| Top-5 accuracy | **85.0%** (17/20) |

| ID | Source | Correct | Top-1 | Top-5 | Top prediction |
|---|---|---|---|---|---|
| V01 | CVE-2021-44228 Log4Shell | T1190 | miss | **hit** | T1027.001 Binary Padding (0.519) |
| V02 | CVE-2017-0144 EternalBlue | T1210, T1486 | miss | **hit** | T1689 Downgrade Attack (0.704) |
| V03 | CVE-2019-0708 BlueKeep | T1210 | **hit** | **hit** | T1210 Exploitation of Remote Services (0.706) |
| V04 | CVE-2020-1472 Zerologon | T1068 | miss | miss | T1556.001 Domain Controller Authentication (0.654) |
| V05 | CVE-2021-34527 PrintNightmare | T1068 | miss | miss | T1547.012 Print Processors (0.750) |
| V06 | CVE-2014-6271 Shellshock | T1190 | miss | **hit** | T1505.003 Web Shell (0.616) |
| V07 | CVE-2017-5638 Apache Struts | T1190 | **hit** | **hit** | T1190 Exploit Public-Facing Application (0.591) |
| V08 | CVE-2021-26855 ProxyLogon | T1190 | miss | **hit** | T1114.002 Remote Email Collection (0.613) |
| V09 | CVE-2023-34362 MOVEit/Cl0p | T1190 | **hit** | **hit** | T1190 Exploit Public-Facing Application (0.698) |
| V10 | CVE-2022-30190 Follina | T1203 | miss | **hit** | T1204.002 Malicious File (0.663) |
| V11 | CVE-2017-11882 Office Equation Editor | T1203 | miss | **hit** | T1566 Phishing (0.690) |
| V12 | CVE-2023-23397 Outlook NTLM leak | T1187 | miss | **hit** | T1557.001 Name Resolution Poisoning and SMB Relay (0.579) |
| V13 | CVE-2018-13379 Fortinet SSL VPN | T1190, T1552.001 | **hit** | **hit** | T1190 Exploit Public-Facing Application (0.553) |
| V14 | CVE-2020-0601 CurveBall | T1553.002 | **hit** | **hit** | T1553.002 Code Signing (0.602) |
| V15 | LSASS dumping (Mimikatz) | T1003.001 | **hit** | **hit** | T1003.001 LSASS Memory (0.723) |
| V16 | PowerShell in-memory 2nd stage | T1059.001 | miss | **hit** | T1027.010 Command Obfuscation (0.735) |
| V17 | Macro phishing attachment | T1566.001 | miss | **hit** | T1204.002 Malicious File (0.628) |
| V18 | Scheduled task persistence | T1053.005 | miss | miss | T1688 Safe Mode Boot (0.583) |
| V19 | Cobalt Strike beaconing | T1071.001 | miss | **hit** | T1678 Delay Execution (0.453) |
| V20 | Kerberoasting | T1558.003 | miss | **hit** | T1558 Steal or Forge Kerberos Tickets (0.703, parent technique) |

**What changed:** the original baseline embedded each technique's *entire*
raw description as one vector. `all-MiniLM-L6-v2` truncates at 256 tokens
and mean-pools, so long, digressive descriptions (T1190's, for example,
spends most of its length on ESXi/VMware/cloud edge cases) got averaged away
from their core meaning — T1190 ranked **74th out of 697** techniques against
the Log4Shell query despite being the obviously correct answer. Two fixes
closed most of that gap:

1. **Chunking.** Instead of one embedding per technique, the cleaned
   description (citations/markdown stripped) is split into ~60-word chunks,
   each embedded separately; a technique is scored by its best-matching
   chunk. This stopped irrelevant sentences from dragging down a technique's
   score. (Single-*sentence* chunks were tried first and made top-1 worse —
   short chunks are prone to spurious keyword-overlap matches, e.g. a
   PubPrn sentence mentioning "LDAP://" outscoring Log4Shell's actual JNDI/LDAP
   description. Multi-sentence chunks fixed that.)
2. **Procedure examples.** MITRE's STIX data includes real "Group/Software X
   used T1234 to exploit CVE-Y in..." relationship descriptions per
   technique — concrete, incident-report language much closer to how the
   validation set (and real analysts) phrase things than ATT&CK's own
   abstract technique definitions. Folding up to 25 of these per technique
   into the index gave the matcher vocabulary it didn't have before, and is
   what took T1190 from unrecognizable to a top hit on several CVEs.

**What's still weak:** top-1 (30%) lags top-5 (85%) by a lot — the correct
technique is usually *in* the candidate set but a sibling technique with a
punchier or more lexically-overlapping procedure example (e.g. "Downgrade
Attack" beating EternalBlue's actual technique, T1210) often edges it out for
rank 1. This is a reranking problem, not a recall problem, and is the
natural next thing to fix (see below). T1068 (privilege-escalation CVEs like
Zerologon/PrintNightmare) also remains a consistent miss — the technique
covers so many disparate exploitation scenarios that its procedure examples
don't concentrate strongly around any one of them.

## Limitations

This is a deliberately simple baseline: **SBERT sentence embeddings +
cosine similarity, nothing else.** Known gaps relative to a more complete
approach like ETRI's:

- **No structural ATT&CK graph signal.** Techniques aren't scored using
  their position in the ATT&CK graph (tactic membership, sub-technique
  hierarchy, related/duplicate techniques, technique-to-group/software
  relationships). A method that uses this structure can disambiguate
  between semantically similar but tactically distinct techniques (e.g.
  two techniques with overlapping vocabulary but different kill-chain
  positions), which plain cosine similarity cannot do.
- **No ensembling.** A single embedding model and a single similarity
  metric are used. Ensemble approaches (combining multiple embedding
  models, lexical methods like TF-IDF/BM25, and/or graph-based signal)
  consistently outperform any single method alone on this kind of
  retrieval task.
- **No domain fine-tuning.** `all-MiniLM-L6-v2` is a general-purpose
  sentence embedding model, not fine-tuned on CTI/ATT&CK-specific text.
  Folding in procedure examples (see [Validation results](#validation-results))
  gave it better vocabulary to work with, but a model actually fine-tuned on
  ATT&CK/CTI text or CVE-to-technique pairs would likely separate techniques
  with overlapping general-English vocabulary (e.g. many techniques mention
  "execute," "access," or "file") much better.
- **No reranking.** Every chunk (description or procedure example) counts
  equally once it's the best match for its technique; there's no second pass
  that considers, e.g., how many of a technique's chunks matched, or
  cross-encodes the query against the top candidates for a sharper top-1
  decision. This is the main reason top-5 (85%) is much higher than top-1
  (30%) — the right answer is usually retrieved but not always ranked first.
- **Metric is simplified.** This project reports plain top-1 / top-5
  accuracy over the full ~200-technique universe. Published work in this
  space often reports something like a **Recall@restricted** metric, which
  narrows the candidate set to a more realistic subset (e.g. techniques
  plausible for the relevant tactic or platform) before scoring — a fairer
  and harder-to-game measure than raw top-k over every technique.
- **Small, hand-built validation set.** 20 examples is enough to sanity-check
  the approach, not to produce a statistically rigorous accuracy estimate.
  Real evaluation would need hundreds of labeled examples, ideally drawn
  from an existing public CVE-to-ATT&CK mapping corpus rather than manually
  curated.
- **Single-label bias in scoring.** Some real incidents legitimately map to
  multiple techniques (initial access **and** the technique it enables);
  this tool returns a flat ranked list rather than reasoning about
  attack-chain structure (e.g. the CTID "exploitation → primary impact →
  secondary impact" framing used in CVE-to-ATT&CK mapping methodology).

## What I'd explore next

- **Rerank the top-k.** Retrieval (top-5, 85%) is much stronger than ranking
  (top-1, 30%) — a cross-encoder pass (or even a simple heuristic like
  counting how many of a technique's chunks appear in the query's overall
  top N) over just the top ~10-20 candidates would likely close most of that
  gap without the cost of cross-encoding the whole corpus per query.
- Add lexical retrieval (BM25/TF-IDF) as a second signal and blend/ensemble
  it with the SBERT score — procedure-example chunks in particular often
  contain distinctive terms (product names, CVE IDs) that lexical matching
  would catch directly.
- Incorporate ATT&CK's tactic and sub-technique structure as a re-ranking
  signal (e.g. boost candidates whose tactic is consistent with keywords in
  the query, or roll sub-technique scores up to their parent technique).
- Fine-tune (or at least further pre-train) the embedding model on
  ATT&CK/CTI text — technique descriptions, procedure examples, and CTI
  report excerpts — rather than using an off-the-shelf general model.
- Grow the validation set using an existing public CVE-to-ATT&CK mapping
  dataset (e.g. the Center for Threat-Informed Defense's `attack_to_cve` /
  Mappings Explorer project) instead of hand-curated examples, and adopt a
  Recall@restricted-style metric for a fairer comparison.

## Project structure

```
data/     cached ATT&CK techniques + embeddings (generated, not hand-edited)
src/      ingestion, embedding, and query/matching scripts
eval/     validation set, evaluation script, results
app.py    optional Streamlit demo UI
```

## Tech stack

`sentence-transformers` (all-MiniLM-L6-v2) · `mitreattack-python` ·
`scikit-learn` · `pandas` / `numpy` · `streamlit` (optional demo)

Runs fully offline after the first model download and ATT&CK data fetch —
no external API calls, no cost, CPU only.

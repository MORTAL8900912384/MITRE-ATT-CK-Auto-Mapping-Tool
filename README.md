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

## Why this instead of just asking an LLM?

A fair question, since ChatGPT/Gemini/Claude can already do a decent job of
mapping a CVE description to an ATT&CK technique conversationally. Worth
being honest about this rather than overselling the tool:

**For a single one-off question, a frontier chatbot probably gives a
*better* answer than this tool.** Its top-1 accuracy is 37.5% (see
[Validation results](#validation-results)) because it's doing nearest-neighbor
vocabulary matching against a fixed corpus, not actually reasoning about
exploit mechanics the way an LLM can. So the pitch here isn't "more
accurate than Claude" — it's a set of operational properties general
chatbots aren't built to give you:

- **Can't hallucinate an ID that doesn't exist.** This tool only ever
  returns real technique IDs pulled from the fixed ~700-entry ATT&CK corpus.
  LLMs confidently invent plausible-but-wrong sub-technique numbers more
  often than you'd like (dotted IDs like `T1053.005` are easy to
  misremember) — risky if that ID ends up in a report or a detection rule
  unchecked.
- **Batchable.** It's a script, not a chat turn — point it at 10,000 CVEs or
  a day's worth of SIEM alerts unattended. Pasting into a chatbot doesn't
  scale past a handful of lookups.
- **Deterministic.** Same input → same output, every time. A chatbot's
  answer can vary between calls, or silently drift when the provider
  updates the underlying model — a problem if the output feeds a detection
  rule or a compliance mapping that needs to stay stable.
- **Private / fully offline.** Nothing about the incident text leaves the
  machine it runs on. Some SOCs are contractually or legally barred from
  pasting live incident-response data into a third-party API; this runs
  entirely local after the one-time setup.
- **Auditable.** Every result comes with a similarity score and the
  specific chunk it matched on (a description sentence or a real
  procedure example) — not just a paragraph of black-box reasoning to take
  on faith.

**The strongest setup is probably neither alone.** Use this tool as a fast,
free, deterministic first pass to shortlist a handful of candidates across a
whole queue of alerts, then have an LLM make the final judgment call over
that shortlist — the same "reranker" idea explored under
[Validation results](#validation-results), just swapping a fine-tuned
cross-encoder for an LLM prompt. That combines this tool's scale and
determinism with an LLM's actual reasoning, instead of picking one over the
other.

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
   (not an average), and returns the top-5 techniques by that score. This is
   the default and best-benchmarked path. An opt-in `rerank=True` mode also
   exists (BM25 lexical-rescue candidates + cross-encoder reranking) but is
   off by default because it currently benchmarks worse — see
   [Validation results](#validation-results) for why it's kept anyway.

4. **Validation** ([eval/](eval/))
   A hand-built set of 40 examples ([eval/validation_set.json](eval/validation_set.json))
   pairs real CVE descriptions (Log4Shell, EternalBlue, BlueKeep, Zerologon,
   ProxyLogon, MOVEit/Cl0p, Follina, Citrix/Confluence RCEs, etc., sourced
   from public CVE write-ups and well-documented ATT&CK-CVE mappings) and
   generic attacker-behavior descriptions across a wider spread of tactics
   (credential access, persistence, discovery, collection, exfiltration,
   defense evasion, lateral movement, cloud) with the technique(s) they
   should map to. [eval/evaluate.py](eval/evaluate.py) runs the matcher over
   the set and reports top-1 and top-5 accuracy.

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

# ...add --rerank to try the experimental BM25-rescue + cross-encoder reranking path
# (off by default — see Validation results for why)

# 3. Run the validation set
python eval/evaluate.py

# 4. (Optional) Streamlit demo
streamlit run app.py
```

## Validation results

Run `python eval/evaluate.py` to reproduce. Results as of last run against
the 40-example validation set (`eval/results.json` has full per-example
detail):

| Metric | Score |
|---|---|
| Top-1 accuracy | **37.5%** (15/40) |
| Top-5 accuracy | **80.0%** (32/40) |

<details>
<summary>Full per-example results (click to expand)</summary>

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
| V21 | CVE-2019-19781 Citrix ADC path traversal | T1190 | miss | **hit** | T1187 Forced Authentication (0.557) |
| V22 | CVE-2022-26134 Confluence OGNL injection | T1190 | **hit** | **hit** | T1190 Exploit Public-Facing Application (0.566) |
| V23 | CVE-2023-3519 Citrix ADC buffer overflow | T1190 | **hit** | **hit** | T1190 Exploit Public-Facing Application (0.569) |
| V24 | Golden Ticket | T1558.001 | miss | **hit** | T1558 Steal or Forge Kerberos Tickets (0.716) |
| V25 | Pass-the-Hash | T1550.002 | miss | miss | T1187 Forced Authentication (0.662) |
| V26 | Pass-the-Ticket | T1550.003 | miss | **hit** | T1558 Steal or Forge Kerberos Tickets (0.748) |
| V27 | DLL side-loading | T1574.001 | **hit** | **hit** | T1574.001 DLL (0.762) |
| V28 | Cron persistence | T1053.003 | **hit** | **hit** | T1053.003 Cron (0.617) |
| V29 | Stolen VPN credentials | T1133 | miss | **hit** | T1078 Valid Accounts (0.628) |
| V30 | Cloud IAM role-assumption abuse | T1078.004 | miss | **hit** | T1548.005 Temporary Elevated Cloud Access (0.746) |
| V31 | DNS exfiltration | T1048.003 | miss | miss | T1584.001 Domains (0.626) |
| V32 | Ransomware disabling shadow copies | T1490 | **hit** | **hit** | T1490 Inhibit System Recovery (0.775) |
| V33 | Clearing Windows event logs | T1685.005 | **hit** | **hit** | T1685.005 Clear Windows Event Logs (0.613) |
| V34 | certutil LOLBin download | T1105 | miss | miss | T1041 Exfiltration Over C2 Channel (0.576) |
| V35 | Domain computer enumeration | T1018 | miss | miss | T1078.002 Domain Accounts (0.718) |
| V36 | BEC inbox forwarding rule | T1114.003 | miss | miss | T1586 Compromise Accounts (0.665) |
| V37 | Pre-exfiltration archiving | T1560.001 | **hit** | **hit** | T1560.001 Archive via Utility (0.705) |
| V38 | Session cookie theft | T1539 | **hit** | **hit** | T1539 Steal Web Session Cookie (0.750) |
| V39 | PsExec lateral movement | T1569.002 | **hit** | **hit** | T1569.002 Service Execution (0.713) |
| V40 | Internal port scanning | T1046 | miss | **hit** | T1016 System Network Configuration Discovery (0.659) |

</details>

**How the pipeline got here:** the original baseline embedded each
technique's *entire* raw description as one vector. `all-MiniLM-L6-v2`
truncates at 256 tokens and mean-pools, so long, digressive descriptions
(T1190's, for example, spends most of its length on ESXi/VMware/cloud edge
cases) got averaged away from their core meaning — T1190 ranked **74th out
of 697** techniques against the Log4Shell query despite being the obviously
correct answer. Two fixes closed most of that gap:

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

### Three follow-up experiments (and why only the validation-set growth stuck)

The validation set was grown from 20 to 40 examples (adding more T1190 CVEs,
credential-access/lateral-movement sub-technique triplets that are easy to
confuse with each other — Golden Ticket / Pass-the-Hash / Pass-the-Ticket —
and broader tactic coverage: discovery, exfiltration, cloud, defense
evasion) to get a more reliable signal before tuning further. That alone
moved the numbers from 30%/85% (n=20) to 37.5%/80.0% (n=40) — a reminder
that 20 examples wasn't enough to trust small deltas.

Three more changes were then tried, each with a clear hypothesis for why it
should help. All three were measured honestly, and two made things worse:

| Change | Hypothesis | Result | Kept? |
|---|---|---|---|
| Swap `all-MiniLM-L6-v2` → `all-mpnet-base-v2` / `multi-qa-mpnet-base-dot-v1` | A larger, more accurate general embedding model should separate techniques better | top-1 **dropped** to 30.0% / 32.5% (from 37.5%), top-5 roughly flat (82.5% / 55.0% vs 80.0%), and 6-7x slower to build | **No** |
| Blend BM25 lexical score into the ranking (weighted sum with cosine) | Catches exact terms (CVE IDs, product names) embeddings can blur | top-5 **dropped** to 72.5% (from 80.0%). Per-query min-max normalization stretches even a *weak* BM25 match up to 1.0, so it gets treated as a strong signal and can outweigh a good semantic match | **No** (see below for what *did* stick) |
| Rerank the top ~20-30 candidates with a cross-encoder | A joint (query, passage) encoder should judge relevance more sharply than independently-computed embeddings | top-1 **dropped** to 25.0%, top-5 to 62.5% with `ms-marco-MiniLM-L-6-v2`; two other cross-encoders tried (`stsb-distilroberta-base`, `qnli-distilroberta-base`) were worse still (down to 5.0%/47.5%). All three gave semantically-*irrelevant* candidates similarly-negative scores to the correct one — none of them are trained on anything resembling this domain (short incident text vs. formal ATT&CK technique/procedure text) | **No** |

What stuck from the BM25 work: instead of blending scores, BM25 is used to
**widen the candidate pool** — it can add techniques with genuine lexical
overlap that semantic similarity ranked too low to include in its own
top-20, but it never reorders or removes anything semantic already found.
This is monotonically safe (can't make the pool worse) and measurably
useful: it lifted top-20 pool recall from 90% to 95% on the validation set.
The catch is that widening the pool only matters if something afterward can
promote a rescued candidate into the top 5 — and that's exactly the
reranking step that benchmarked worse. So today, with reranking off by
default, the BM25 pool-widening logic runs but has no effect on the final
top-5 output. It's implemented and available behind `rerank=True`
(`src/query.py`) for when a better-suited reranker is dropped in.

**Why this is still the right way to report it:** all three ideas were
reasonable and are standard techniques in retrieval systems generally — the
finding isn't "these techniques don't work," it's "these *off-the-shelf*
components don't transfer to this specific, narrow domain (~700-technique
ATT&CK corpus, short free-text queries) without further adaptation."
Shipping the version that's actually measured to perform best (plain
semantic chunk-matching, 37.5%/80.0%) rather than the version with the most
moving parts is the point of having a validation set at all.

**What's still weak:** top-1 (37.5%) lags top-5 (80.0%) by a lot — the
correct technique is usually *in* the candidate set but a sibling technique
with a punchier or more lexically-overlapping procedure example (e.g.
"Downgrade Attack" beating EternalBlue's actual technique, T1210) often
edges it out for rank 1. T1068 (privilege-escalation CVEs like
Zerologon/PrintNightmare) and the Pass-the-Hash/Pass-the-Ticket/Golden
Ticket trio remain consistent misses — these are cases where several
techniques are genuinely close in meaning and only a sharper (fine-tuned,
domain-specific) reranker is likely to reliably separate them.

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
- **No ensembling that actually helps yet.** A weighted blend of embedding
  score + BM25, a larger embedding model, and cross-encoder reranking were
  all tried (see [Validation results](#validation-results)) and each
  underperformed the plain semantic-only baseline on this corpus. The
  underlying idea (combine multiple signals) is still sound in general — the
  specific off-the-shelf components tried just didn't transfer to this
  narrow a domain.
- **No domain fine-tuning.** `all-MiniLM-L6-v2` is a general-purpose
  sentence embedding model, not fine-tuned on CTI/ATT&CK-specific text.
  Folding in procedure examples (see [Validation results](#validation-results))
  gave it better vocabulary to work with, but a model actually fine-tuned on
  ATT&CK/CTI text or CVE-to-technique pairs would likely separate techniques
  with overlapping general-English vocabulary (e.g. many techniques mention
  "execute," "access," or "file") much better — and would likely also make
  cross-encoder reranking (see above) actually pay off, since a fine-tuned
  reranker would be judging relevance in-domain instead of on web-search or
  generic-STS notions of relevance.
- **Metric is simplified.** This project reports plain top-1 / top-5
  accuracy over the full ~700-technique universe. Published work in this
  space often reports something like a **Recall@restricted** metric, which
  narrows the candidate set to a more realistic subset (e.g. techniques
  plausible for the relevant tactic or platform) before scoring — a fairer
  and harder-to-game measure than raw top-k over every technique.
- **Still a fairly small, hand-built validation set.** 40 examples (grown
  from an initial 20) is enough to catch large effects and rule out
  regressions with reasonable confidence, but individual examples still
  swing the percentage by 2.5 points each — not enough for fine-grained
  statistical comparisons between close configurations. Real evaluation
  would need hundreds of labeled examples, ideally drawn from an existing
  public CVE-to-ATT&CK mapping corpus rather than manually curated.
- **Single-label bias in scoring.** Some real incidents legitimately map to
  multiple techniques (initial access **and** the technique it enables);
  this tool returns a flat ranked list rather than reasoning about
  attack-chain structure (e.g. the CTID "exploitation → primary impact →
  secondary impact" framing used in CVE-to-ATT&CK mapping methodology).

## What I'd explore next

- **A domain-adapted reranker, not a bigger off-the-shelf one.** Three
  general-purpose cross-encoders were tried for top-k reranking and all
  three made results worse (see [Validation results](#validation-results));
  the pattern strongly suggests the problem is domain transfer, not the
  reranking *idea*. Fine-tuning a small cross-encoder on
  (query, technique-chunk) pairs — even a few hundred synthetic or
  CTID-sourced examples — would be the highest-value next step, and the
  BM25 pool-widening + reranking plumbing (`rerank=True` in `src/query.py`)
  is already built and ready for it.
- Incorporate ATT&CK's tactic and sub-technique structure as a reranking
  signal (e.g. boost candidates whose tactic is consistent with keywords in
  the query, or roll sub-technique scores up to their parent technique) —
  untried so far, and doesn't depend on a better reranker model to test.
- Grow the validation set further using an existing public CVE-to-ATT&CK
  mapping dataset (e.g. the Center for Threat-Informed Defense's
  `attack_to_cve` / Mappings Explorer project) instead of hand-curated
  examples, and adopt a Recall@restricted-style metric for a fairer
  comparison — 40 examples was enough to catch the regressions above, but
  not enough to confidently tune finer details like chunk size or pool size.

## Project structure

```
data/     cached ATT&CK techniques + embeddings (generated, not hand-edited)
src/      ingestion, embedding, and query/matching scripts
eval/     validation set, evaluation script, results
app.py    optional Streamlit demo UI
```

## Tech stack

`sentence-transformers` (all-MiniLM-L6-v2, plus a `cross-encoder` used only
behind the experimental `--rerank` flag) · `mitreattack-python` ·
`scikit-learn` · `rank-bm25` · `pandas` / `numpy` · `streamlit` (optional demo)

Runs fully offline after the first model download and ATT&CK data fetch —
no external API calls, no cost, CPU only.

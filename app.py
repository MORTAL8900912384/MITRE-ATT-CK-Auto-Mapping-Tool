"""
Streamlit demo: paste a CVE/incident description in, get ranked ATT&CK
technique matches out. Run with:

    streamlit run app.py
"""

import os
import sys

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from query import get_model, load_index, top_matches  # noqa: E402

st.set_page_config(page_title="ATT&CK Technique Auto-Mapper", page_icon="🎯", layout="centered")

st.title("ATT&CK Technique Auto-Mapper")
st.caption(
    "Paste a CVE description, incident summary, or attacker behavior. "
    "Get the most likely MITRE ATT&CK techniques via SBERT semantic similarity."
)


@st.cache_resource(show_spinner="Loading model and technique index...")
def load_resources():
    model = get_model()
    embeddings, ids, techniques = load_index()
    return model, embeddings, ids, techniques


try:
    model, embeddings, ids, techniques = load_resources()
except FileNotFoundError as e:
    st.error(
        f"{e}\n\nRun `python src/fetch_attack_data.py` then "
        "`python src/build_embeddings.py` before launching the app."
    )
    st.stop()

default_text = (
    "Attacker sent a phishing email with a malicious macro-enabled Word "
    "document; opening it downloaded and executed a PowerShell payload that "
    "dumped credentials from LSASS memory."
)
text = st.text_area("Threat / incident / CVE description", value="", placeholder=default_text, height=140)
top_k = st.slider("Number of matches", min_value=1, max_value=10, value=5)

if st.button("Map to ATT&CK techniques", type="primary") and text.strip():
    with st.spinner("Embedding and ranking..."):
        results = top_matches(
            text, top_k=top_k, model=model, embeddings=embeddings, ids=ids, techniques=techniques
        )

    df = pd.DataFrame(
        [
            {
                "Technique ID": r["technique_id"],
                "Name": r["name"],
                "Tactics": ", ".join(r["tactics"]),
                "Similarity": round(r["score"], 4),
            }
            for r in results
        ]
    )
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.markdown("---")
    for r in results:
        url = f"https://attack.mitre.org/techniques/{r['technique_id'].replace('.', '/')}/"
        st.markdown(f"**[{r['technique_id']}]({url}) {r['name']}** — score {r['score']:.4f}")
elif text.strip() == "":
    st.info("Enter a description above and click the button (or try the placeholder example).")

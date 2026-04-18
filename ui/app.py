"""
DepGraph — Streamlit UI
Run: streamlit run ui/app.py
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
from agent import ask

st.set_page_config(page_title="DepGraph", page_icon="🔐", layout="centered")
st.title("🔐 DepGraph Agent")
st.caption("Supply chain vulnerability propagation — powered by Neo4j Aura")

EXAMPLES = [
    "Is flask vulnerable?",
    "What is the blast radius of werkzeug?",
    "Show the dependency path from flask to markupsafe",
    "Which packages have the most CVEs?",
    "Find vulnerabilities similar to remote code execution via deserialization",
]

with st.sidebar:
    st.header("Example queries")
    for ex in EXAMPLES:
        if st.button(ex, use_container_width=True):
            st.session_state["query"] = ex
    st.divider()
    st.markdown("""
**Graph schema**
```
(:Package)-[:DEPENDS_ON]->(:Package)
(:Package)-[:HAS_VULNERABILITY]->(:Vulnerability)
```
**Tools**
- Cypher Template — direct lookups & traversals
- Text2Cypher — ad-hoc queries
- Similarity Search — attack pattern matching
""")

if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

default_query = st.session_state.pop("query", "")
query = st.chat_input("Ask about a package, CVE, or dependency path...") or default_query

if query:
    st.session_state.messages.append({"role": "user", "content": query})
    with st.chat_message("user"):
        st.markdown(query)
    with st.chat_message("assistant"):
        with st.spinner("Traversing the dependency graph..."):
            answer = ask(query)
        st.markdown(answer)
    st.session_state.messages.append({"role": "assistant", "content": answer})

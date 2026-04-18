# 🔐 DepGraph Agent

> *"Which of my packages are affected by this CVE — and through how many hops?"*

DepGraph is a supply chain security agent that traces vulnerability propagation through PyPI dependency graphs using Neo4j Aura. It answers questions no flat database can: not just *is this package vulnerable*, but *who depends on it, through what path, and what's the blast radius*.

---

## The Problem

When Log4Shell dropped in 2021, thousands of teams scrambled to answer one question: **are we affected?** The answer wasn't in any single package — it was buried in transitive dependency chains 3–4 hops deep. A flat database can list vulnerable packages. Only a graph can trace the propagation.

DepGraph makes that traversal instant and explainable.

---

## What It Does

| Query | Tool used | What the graph does |
|-------|-----------|---------------------|
| "Is flask vulnerable?" | Cypher Template | Direct `HAS_VULNERABILITY` lookup |
| "What's the blast radius of werkzeug?" | Cypher Template | 4-hop `DEPENDS_ON*1..4` traversal — finds every upstream package that transitively depends on werkzeug AND has its own CVEs |
| "Show the path from flask to markupsafe" | Cypher Template | `shortestPath` across `DEPENDS_ON` edges |
| "Which packages have the most CVEs?" | Cypher Template | Aggregation over `HAS_VULNERABILITY` edges |
| "Find vulns like remote code execution via deserialization" | Similarity Search | Vector search on OSV vuln summaries |
| "How many CRITICAL vulns were published in 2023?" | Text2Cypher | Ad-hoc Cypher generated at runtime |

---

## Why a Graph Fits This Dataset

Dependency relationships are **the data**. The insight is never in a single node — it's in the chain:

```
flask → werkzeug → (CVE-2023-25577: high severity)
      ↑
  your app depends on flask
  → your app is transitively exposed
```

A SQL query for this requires recursive CTEs that break at scale and can't explain the path. A graph traversal returns the full chain in milliseconds and makes the reasoning transparent.

**Graph stats:**
- ~200+ Package nodes
- ~300+ Vulnerability nodes (real OSV data)
- ~500+ `DEPENDS_ON` edges
- ~400+ `HAS_VULNERABILITY` edges

---

## Graph Schema

```
(:Package {name, version, summary})
(:Vulnerability {id, summary, severity, published, embedding})

(:Package)-[:DEPENDS_ON]->(:Package)
(:Package)-[:HAS_VULNERABILITY]->(:Vulnerability)
```

---

## Dataset

**Source:** No Kaggle needed — two free public APIs:
- **PyPI JSON API** (`pypi.org/pypi/<pkg>/json`) — package metadata and dependency lists
- **OSV API** (`api.osv.dev/v1/query`) — real CVE/GHSA vulnerability data for PyPI packages

25 seed packages (flask, django, requests, cryptography, pillow, etc.) + 1 hop of their dependencies. All vulnerability data is live from the OSV database.

---

## Setup

### 1. Aura Console (do this first)

In [console.neo4j.io](https://console.neo4j.io) → Organization Settings:
- Toggle **Generative AI assistance** ON
- Toggle **Aura Agent** ON
- Security → **Tool authentication** ON
- Confirm your project role is **Project Admin**

### 2. Install Ollama and pull models (free, local)

```bash
# Install Ollama: https://ollama.com/download
ollama pull llama3.2          # LLM (~2GB)
ollama pull nomic-embed-text  # embeddings (~274MB)
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
cp .env.example .env   # only Neo4j credentials needed, no API keys
```

### 3. Fetch data

```bash
python scripts/fetch_data.py
# ~5 min — hits PyPI + OSV APIs, writes data/packages.json + data/vulnerabilities.json
```

### 4. Load graph

```bash
python scripts/load_graph.py
# Creates constraints, vector index (vuln_embeddings), loads all nodes/edges + embeddings
```

### 5. Run

```bash
streamlit run ui/app.py
```

---

## Project Structure

```
depgraph/
├── scripts/
│   ├── fetch_data.py     # PyPI + OSV API fetcher
│   └── load_graph.py     # Neo4j loader + embedding generator
├── agent/
│   ├── __init__.py
│   └── depgraph.py       # Agent: 4 Cypher templates + Text2Cypher + Similarity Search
├── ui/
│   └── app.py            # Streamlit chat UI
├── requirements.txt
└── .env.example
```

---

## Tech Stack

- **Neo4j Aura Free** — managed graph database
- **neo4j-graphrag** — Text2Cypher + VectorRetriever
- **Ollama** — local, free, no API key required
  - `llama3.2` — LLM for answer synthesis and Text2Cypher
  - `nomic-embed-text` — 768-dim embeddings for vulnerability similarity search
- **OSV API** — real-world vulnerability data
- **PyPI API** — live dependency graph
- **Streamlit** — chat UI

---

## Hackathon Submission

**Agent Name:** DepGraph Agent

**What it does:**
Traces vulnerability propagation through PyPI dependency chains. Answers "is X vulnerable?", "what's the blast radius of Y?", "show me the path from A to B", and "find CVEs matching this attack pattern" — all grounded in a live graph of real packages and real OSV vulnerability data.

**Dataset and why a graph fits:**
PyPI dependency data + OSV vulnerability database. A graph fits because the entire problem *is* relationships — transitive dependencies are multi-hop graph traversals. There is no meaningful way to answer "what's the blast radius of werkzeug?" without traversing edges. A flat table can tell you werkzeug has CVEs. Only a graph can tell you that flask depends on werkzeug, and your app depends on flask, so you're exposed through a 2-hop chain.

**Why the graph matters:**
Every answer DepGraph gives includes the dependency path — not just the result. "Flask is exposed because it depends on Werkzeug 2.1.0 which has CVE-2023-25577 (HIGH severity, path injection)." That's relationship-driven explanation, not a lookup.

# 🔐 DepGraph Agent

> *"Which of my packages are affected by this CVE — and through how many hops?"*

DepGraph Agent turns your PyPI dependency tree into a knowledge graph that reasons about supply chain security. It answers questions no flat database can: "What's the blast radius of werkzeug?" "Why is my app exposed to CVE-2023-25577?" "How does a vulnerability in a low-level library propagate up to my top-level packages?"

PyPI packages have hundreds of transitive dependencies, but most tools only show you direct CVEs. You can see *what* is vulnerable — never *why your app is affected*. DepGraph connects the dots by building a graph where packages, their dependency relationships, and known OSV vulnerabilities are linked through explicit edges. The agent then uses multi-hop graph reasoning to trace propagation paths that are invisible in flat dashboards.

---

## What It Does

| Query | Tool | What the graph does |
|-------|------|---------------------|
| "Is flask vulnerable?" | Cypher Template | Direct `HAS_VULNERABILITY` lookup |
| "What's the blast radius of werkzeug?" | Cypher Template | 4-hop `DEPENDS_ON*1..4` traversal — every upstream package transitively depending on werkzeug that also carries CVEs |
| "Show the path from flask to markupsafe" | Cypher Template | `shortestPath` across `DEPENDS_ON` edges |
| "Which packages have the most CVEs?" | Cypher Template | Aggregation over `HAS_VULNERABILITY` edges |
| "Find vulns like remote code execution via deserialization" | Similarity Search | Vector search on OSV vuln summaries (3072-dim embeddings) |
| "How many CRITICAL vulns were published in 2023?" | Text2Cypher | Ad-hoc Cypher generated at runtime by the LLM |

### Example conversation

**User:** "What's the blast radius of werkzeug?"

**Agent reasoning (multi-hop):**
1. Finds all packages with `DEPENDS_ON*1..4` path to `werkzeug`
2. Filters to those that also have `HAS_VULNERABILITY` edges
3. Returns affected packages with hop count, vuln count, and sample CVEs

**Agent response:**
> *Flask depends on Werkzeug 3.1.3 (1 hop) and carries 20 known vulnerabilities including CVE-2023-25577 (HIGH — path injection) and CVE-2023-46136 (HIGH — DoS via multipart). Any application depending on flask is transitively exposed through this 2-hop chain. Starlette also depends on werkzeug indirectly (2 hops) with 7 additional vulnerabilities in the chain.*

This answer requires traversing 4 hops through the graph. No flat database produces it.

---

## Dataset and Why a Graph Fits

**Sources (both free, no auth required):**
- [PyPI JSON API](https://pypi.org/pypi/<pkg>/json) — live package metadata and dependency lists
- [OSV API](https://api.osv.dev/v1/query) — real CVE/GHSA vulnerability data for PyPI packages

25 seed packages (flask, django, requests, cryptography, pillow, urllib3, celery, etc.) + 1 hop of their dependencies, yielding **269 packages, 62 vulnerable packages, 801 real vulnerabilities**.

**Why a graph is the only way to solve this:**

A table can tell you werkzeug has CVEs. Only a graph can tell you that flask depends on werkzeug, and your app depends on flask, so you're exposed through a 2-hop chain:

```
your-app
  └─[:DEPENDS_ON]─> flask
                      └─[:DEPENDS_ON]─> werkzeug
                                          └─[:HAS_VULNERABILITY]─> CVE-2023-25577 (HIGH)
```

When Log4Shell dropped in 2021, teams needed to know their blast radius across 3–4 hops of transitive dependencies. That's a graph traversal problem — recursive CTEs in SQL break at scale and can't explain the path. A graph returns the full chain in milliseconds and makes the reasoning transparent.

**Graph schema:**
```
(:Package {name, version, summary})
(:Vulnerability {id, summary, severity, published, embedding})

(:Package)-[:DEPENDS_ON]->(:Package)
(:Package)-[:HAS_VULNERABILITY]->(:Vulnerability)
```

**Graph stats:**
- 269 `Package` nodes
- 801 `Vulnerability` nodes (real OSV data, 3072-dim embeddings)
- 500+ `DEPENDS_ON` edges
- 400+ `HAS_VULNERABILITY` edges

---

## What Makes This Different

**1. The graph drives the insight, not just stores data.**
Every answer traces a relationship path. "Your app is exposed because..." always cites the specific package → dependency → CVE chain that explains it. The agent never gives a lookup result without the graph path that produced it.

**2. Real data, live APIs.**
No synthetic datasets, no Kaggle downloads. Every vulnerability is pulled live from the OSV database. Every dependency edge is pulled live from PyPI. The graph reflects the actual state of the ecosystem.

**3. Similarity search on attack patterns.**
Vulnerability embeddings (3072-dim via Gemini) enable semantic queries like "find CVEs similar to SQL injection in ORM layer" — matching by attack pattern, not just CVE ID. This surfaces related vulnerabilities across different packages that a keyword search would miss.

**4. The agent explains its reasoning.**
The tool used and its purpose are included in every LLM prompt. When the agent says "werkzeug has 20 CVEs affecting flask," it shows which tool it used and what graph data it retrieved.

---

## Setup

### 1. Get credentials

- **Neo4j Aura Free** — [console.neo4j.io](https://console.neo4j.io) → Create free instance
- **Gemini API key** (embeddings only) — [aistudio.google.com/apikey](https://aistudio.google.com/apikey) — no credit card
- **Groq API key** (LLM) — [console.groq.com/keys](https://console.groq.com/keys) — free tier, 14,400 req/day

### 2. Configure

```bash
cp .env.example .env
# Fill in NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, GEMINI_API_KEY, GROQ_API_KEY
```

### 3. Install

```bash
pip install -r requirements.txt
```

### 4. Fetch data

```bash
python scripts/fetch_data.py
# ~5 min — hits PyPI + OSV APIs
# Output: data/packages.json, data/vulnerabilities.json
```

### 5. Load graph

```bash
python scripts/load_graph.py
# Creates constraints + vector index, loads nodes/edges + embeddings
# Handles rate limits automatically with retry + resume support
```

### 6. Run

```bash
streamlit run ui/app.py
```

---

## Project Structure

```
depgraph/
├── scripts/
│   ├── fetch_data.py     # PyPI + OSV API fetcher
│   └── load_graph.py     # Neo4j loader + embedding generator (with resume support)
├── agent/
│   ├── __init__.py
│   └── depgraph.py       # Agent: 4 Cypher templates + Text2Cypher + Similarity Search
├── ui/
│   └── app.py            # Streamlit chat UI
├── data/
│   ├── packages.json     # 269 packages with dependency edges
│   └── vulnerabilities.json  # 801 real OSV vulnerabilities
├── requirements.txt
└── .env.example
```

---

## Tech Stack

- **Neo4j Aura Free** — managed graph database
- **neo4j-graphrag** — Text2Cypher + VectorRetriever
- **Groq** (`llama-3.3-70b-versatile`) — LLM for answer synthesis and Text2Cypher (free tier)
- **Google Gemini** (`gemini-embedding-001`, 3072-dim) — vulnerability embeddings
- **OSV API** — real-world vulnerability data
- **PyPI API** — live dependency graph
- **Streamlit** — chat UI

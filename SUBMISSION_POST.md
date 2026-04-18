# DepGraph Agent

## What it does

DepGraph is a supply chain security agent that traces **vulnerability propagation through PyPI dependency chains** using a Neo4j knowledge graph.

It answers questions no flat database can:

- **"Is flask vulnerable?"** → direct CVE lookup via graph traversal
- **"What's the blast radius of werkzeug?"** → finds every package that transitively depends on werkzeug (up to 4 hops) and is also vulnerable
- **"Show the dependency path from flask to markupsafe"** → shortest path across `DEPENDS_ON` edges
- **"Which packages have the most CVEs?"** → aggregation over `HAS_VULNERABILITY` relationships
- **"Find vulnerabilities similar to remote code execution via deserialization"** → vector similarity search on OSV vuln summaries

The agent always explains *why* using the graph path — not just the result. Example response:

> *"Flask is transitively exposed: flask → werkzeug 2.1.0 → CVE-2023-25577 (HIGH severity, path injection). This is a 1-hop dependency chain. Werkzeug also carries 3 additional MODERATE vulnerabilities affecting the same version range."*

---

## Dataset and why a graph fits

**Sources (both free, no signup):**
- [PyPI JSON API](https://pypi.org/pypi/<pkg>/json) — live package metadata and dependency lists
- [OSV API](https://api.osv.dev/v1/query) — real CVE/GHSA vulnerability data for PyPI packages

25 seed packages (flask, django, requests, cryptography, pillow, urllib3, etc.) + their direct dependencies, yielding:

- ~200+ `Package` nodes
- ~300+ `Vulnerability` nodes (real OSV data)
- ~500+ `DEPENDS_ON` edges
- ~400+ `HAS_VULNERABILITY` edges

**Why a graph is the only way to solve this:**

Dependency relationships *are* the data. The insight is never in a single node — it's in the chain:

```
your-app → flask → werkzeug → [CVE-2023-25577]
```

A SQL query for transitive exposure requires recursive CTEs that break at scale and can't explain the path. A graph traversal returns the full chain in milliseconds and makes the reasoning transparent. When Log4Shell dropped, teams needed to know their blast radius across 3–4 hops of transitive dependencies — that's a graph problem, not a table problem.

**Graph schema:**
```
(:Package {name, version, summary})
(:Vulnerability {id, summary, severity, published, embedding})

(:Package)-[:DEPENDS_ON]->(:Package)
(:Package)-[:HAS_VULNERABILITY]->(:Vulnerability)
```

---

## Tools

| Tool | Type | When used |
|------|------|-----------|
| `direct_vulns` | Cypher Template | "Is X vulnerable?" — direct `HAS_VULNERABILITY` lookup |
| `blast_radius` | Cypher Template | "What's the blast radius of X?" — `DEPENDS_ON*1..4` traversal |
| `dep_path` | Cypher Template | "Path from A to B?" — `shortestPath` across dependency edges |
| `top_vulnerable` | Cypher Template | "Most vulnerable packages?" — aggregation query |
| `ad_hoc_query` | Text2Cypher | Any question not covered by a template |
| `vuln_similarity` | Similarity Search | "Find CVEs like [attack description]" — vector search on OSV summaries |

---

## Screenshot of agent in Aura Console

> 📸 *[Insert screenshot of agent configuration in Data Services → Agents showing all 6 tools]*

---

## Screenshot of agent in action

> 📸 *[Insert screenshot of Streamlit UI showing a blast radius query response with dependency chain explanation]*

---

## Optional: Link to agent

> 🔗 *[Insert MCP endpoint URL after enabling External access in Aura Console]*

---

## Tech stack

- **Neo4j Aura Free** — managed graph database
- **neo4j-graphrag** — Text2Cypher + VectorRetriever
- **OpenAI** `text-embedding-3-small` — vulnerability embeddings
- **OpenAI** `gpt-4o-mini` — answer synthesis
- **Streamlit** — chat UI
- **OSV API + PyPI API** — live data, no Kaggle required

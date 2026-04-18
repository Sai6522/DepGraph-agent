"""
DepGraph Agent — OSV vulnerability propagation agent.
LLM + Embeddings: Google Gemini API (free tier via AI Studio)
  - LLM:        gemini-2.0-flash
  - Embeddings: text-embedding-004 (768 dims)

Get a free API key (no credit card): https://aistudio.google.com/apikey
"""

import os
import re
from dotenv import load_dotenv
from neo4j import GraphDatabase
import google.generativeai as genai
from groq import Groq
from neo4j_graphrag.llm import LLMInterface, LLMResponse
from neo4j_graphrag.embeddings.base import Embedder
from neo4j_graphrag.retrievers import Text2CypherRetriever, VectorRetriever

load_dotenv()

def _get_env(key: str) -> str:
    # Try os.environ first (local .env), then Streamlit secrets
    if key in os.environ:
        return os.environ[key]
    try:
        import streamlit as st
        return st.secrets[key]
    except Exception:
        raise KeyError(f"Missing required config: {key}")

# ── Groq LLM wrapper ──────────────────────────────────────────────────────────
class GroqLLM(LLMInterface):
    def __init__(self, model_name: str = "llama-3.3-70b-versatile"):
        super().__init__(model_name)
        self.model_name = model_name

    def invoke(self, input: str, **kwargs) -> LLMResponse:
        client = Groq(api_key=_get_env("GROQ_API_KEY"))
        response = client.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "user", "content": input}],
        )
        return LLMResponse(content=response.choices[0].message.content)

    async def ainvoke(self, input: str, **kwargs) -> LLMResponse:
        return self.invoke(input)


# ── custom embedder wrapper for Gemini AI Studio ──────────────────────────────
class GeminiEmbedder(Embedder):
    def __init__(self, model: str = "models/gemini-embedding-001"):
        self.model = model

    def embed_query(self, text: str) -> list[float]:
        genai.configure(api_key=_get_env("GEMINI_API_KEY"))
        result = genai.embed_content(model=self.model, content=text[:2000])
        return result["embedding"]


# ── lazy-initialized globals ──────────────────────────────────────────────────
_driver = None
_llm = None
_embedder = None
_t2c = None
_vector = None

def _init():
    global _driver, _llm, _embedder, _t2c, _vector
    if _driver is not None:
        return
    genai.configure(api_key=_get_env("GEMINI_API_KEY"))
    _driver = GraphDatabase.driver(
        _get_env("NEO4J_URI"),
        auth=(_get_env("NEO4J_USERNAME"), _get_env("NEO4J_PASSWORD")),
    )
    _llm = GroqLLM()
    _embedder = GeminiEmbedder()
    _t2c = Text2CypherRetriever(
        driver=_driver,
        llm=_llm,
        neo4j_schema="""
            Node labels: Package, Vulnerability
            Relationships: (Package)-[:DEPENDS_ON]->(Package), (Package)-[:HAS_VULNERABILITY]->(Vulnerability)
            Package properties: name (string), version (string), summary (string)
            Vulnerability properties: id (string), summary (string), severity (string), published (string)
            Severity values: CRITICAL, HIGH, MODERATE, LOW, UNKNOWN
        """,
    )
    _vector = VectorRetriever(
        driver=_driver,
        index_name="vuln_embeddings",
        embedder=_embedder,
        return_properties=["id", "summary", "severity"],
    )

# ── system prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are DepGraph, a software supply chain security assistant.
You reason over a Neo4j graph of PyPI packages, their dependency relationships, and known OSV vulnerabilities.
Your job is to trace vulnerability propagation through dependency chains and explain the blast radius.
Always explain your answer using graph relationships — show the dependency path, not just the result.
Decline any request unrelated to software dependencies, packages, or security vulnerabilities."""

# ── tool descriptions (LLM picks tools by description only) ──────────────────
TOOL_DESCRIPTIONS = {
    "direct_vulns": (
        "Return all known vulnerabilities for a specific package by name, for example 'flask' or 'requests'. "
        "Use this when the user asks whether a named package is vulnerable or what CVEs affect it. "
        "Parameter: package (string, e.g. 'flask')."
    ),
    "blast_radius": (
        "Trace which packages transitively depend on a given package (up to 4 hops) and return those "
        "that are also vulnerable. Use this when the user asks about the blast radius, impact, or "
        "which packages are affected by a vulnerability in a dependency. "
        "Parameter: package (string, e.g. 'werkzeug')."
    ),
    "dep_path": (
        "Find the shortest dependency path between two packages. Use this when the user asks how "
        "one package is connected to another, or why a vulnerability in package B affects package A. "
        "Parameters: from_pkg (string), to_pkg (string)."
    ),
    "top_vulnerable": (
        "Return the packages with the most known vulnerabilities, ordered by vuln count. "
        "Use this when the user asks which packages are most at risk or have the most CVEs. "
        "Parameter: limit (integer, e.g. 10)."
    ),
    "text2cypher": (
        "Use this tool ONLY when no Cypher Template covers the question. "
        "The graph contains: Package nodes (name, version, summary) and Vulnerability nodes "
        "(id, summary, severity, published). "
        "Relationships: (Package)-[:DEPENDS_ON]->(Package), (Package)-[:HAS_VULNERABILITY]->(Vulnerability). "
        "Severity values: CRITICAL, HIGH, MODERATE, LOW, UNKNOWN. "
        "Do not use this for direct vuln lookup, blast radius, dep path, or top vulnerable — "
        "those have dedicated Cypher Template tools."
    ),
    "similarity_search": (
        "Find vulnerabilities semantically similar to a description using vector search. "
        "Use this when the user describes a vulnerability type or attack pattern rather than a specific "
        "CVE ID or package name — e.g. 'remote code execution via deserialization' or "
        "'SQL injection in ORM layer'."
    ),
}

# ── tool 1: cypher templates ──────────────────────────────────────────────────
CYPHER_TEMPLATES = {
    "direct_vulns": """
        MATCH (p:Package {name: $package})-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN p.name AS package, p.version AS version,
               v.id AS cve, v.severity AS severity, v.summary AS summary
        ORDER BY v.severity DESC
        LIMIT 20
    """,
    "blast_radius": """
        MATCH path = (upstream:Package)-[:DEPENDS_ON*1..4]->(p:Package {name: $package})
        WHERE (upstream)-[:HAS_VULNERABILITY]->()
        WITH upstream, length(path) AS hops
        MATCH (upstream)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN upstream.name AS affected_package,
               upstream.version AS version,
               hops AS dependency_hops,
               collect(v.id)[..3] AS sample_cves,
               count(v) AS vuln_count
        ORDER BY hops, vuln_count DESC
        LIMIT 30
    """,
    "dep_path": """
        MATCH path = shortestPath(
            (a:Package {name: $from_pkg})-[:DEPENDS_ON*]->(b:Package {name: $to_pkg})
        )
        RETURN [n IN nodes(path) | n.name] AS dependency_chain,
               length(path) AS hops
    """,
    "top_vulnerable": """
        MATCH (p:Package)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN p.name AS package, p.version AS version,
               count(v) AS vuln_count,
               collect(DISTINCT v.severity)[..4] AS severities
        ORDER BY vuln_count DESC
        LIMIT $limit
    """,
}


def cypher_template(template_name: str, **params) -> list[dict]:
    _init()
    query = CYPHER_TEMPLATES[template_name]
    with _driver.session() as session:
        return [dict(r) for r in session.run(query, **params)]


# ── tool 2: text2cypher ───────────────────────────────────────────────────────


def text2cypher(question: str) -> list:
    _init()
    result = _t2c.search(query_text=question)
    return [item.content for item in result.items]


# ── tool 3: similarity search ─────────────────────────────────────────────────


def similarity_search(description: str, top_k: int = 7) -> list:
    _init()
    result = _vector.search(query_text=description, top_k=top_k)
    return [item.content for item in result.items]


# ── routing ───────────────────────────────────────────────────────────────────
def _route(question: str) -> tuple[str, list]:
    q = question.lower()

    if re.search(r"\b(similar|like|type of|attack|pattern|rce|xss|sqli|injection|deserialization|overflow)\b", q):
        return "similarity_search", similarity_search(question)

    if re.search(r"\b(blast radius|impact|affected by|propagat|downstream|who depends|which packages.*depend)\b", q):
        pkg = re.search(r"(?:of|on|by|in)\s+['\"]?([a-z0-9_\-\.]+)['\"]?", q)
        if pkg:
            return "blast_radius", cypher_template("blast_radius", package=pkg.group(1))

    path_match = re.search(
        r"(?:path|connect|how).*?['\"]?([a-z0-9_\-\.]+)['\"]?\s+(?:to|and|→)\s+['\"]?([a-z0-9_\-\.]+)['\"]?", q
    )
    if path_match:
        return "dep_path", cypher_template("dep_path", from_pkg=path_match.group(1), to_pkg=path_match.group(2))

    if re.search(r"\b(most vulnerable|most cves|highest risk|top.*vuln|riskiest)\b", q):
        limit_m = re.search(r"\b(\d+)\b", q)
        return "top_vulnerable", cypher_template("top_vulnerable", limit=int(limit_m.group(1)) if limit_m else 10)

    pkg_match = re.search(
        r"(?:is\s+|does\s+|for\s+|in\s+|package\s+|vuln.*in\s+)['\"]?([a-z0-9_\-\.]+)['\"]?(?:\s+vuln|\s+safe|\s+affect|\s+cve|$|\?)",
        q,
    )
    if pkg_match:
        return "direct_vulns", cypher_template("direct_vulns", package=pkg_match.group(1))

    return "text2cypher", text2cypher(question)


# ── public interface ──────────────────────────────────────────────────────────
def ask(question: str) -> str:
    _init()
    tool_used, context_items = _route(question)
    context = "\n".join(str(item) for item in context_items[:12])

    prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"Tool used: {tool_used}\n"
        f"Tool purpose: {TOOL_DESCRIPTIONS[tool_used]}\n\n"
        f"Graph data:\n{context}\n\n"
        f"Question: {question}\n\nAnswer:"
    )
    return _llm.invoke(prompt).content

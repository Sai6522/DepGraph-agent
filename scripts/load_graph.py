"""
Load PyPI dependency graph + OSV vulnerabilities into Neo4j Aura.
Run fetch_data.py first to populate data/.
"""

import json
import os
from pathlib import Path
from dotenv import load_dotenv
from neo4j import GraphDatabase
import google.generativeai as genai

load_dotenv()

genai.configure(api_key=os.environ["GEMINI_API_KEY"])

DATA_DIR = Path(__file__).parent.parent / "data"

driver = GraphDatabase.driver(
    os.environ["NEO4J_URI"],
    auth=(os.environ["NEO4J_USERNAME"], os.environ["NEO4J_PASSWORD"]),
)


def get_embedding(text: str) -> list[float]:
    import time
    for attempt in range(5):
        try:
            result = genai.embed_content(model="models/gemini-embedding-001", content=text[:2000])
            return result["embedding"]
        except Exception as e:
            if "429" in str(e) or "ResourceExhausted" in type(e).__name__:
                wait = 15 * (attempt + 1)
                print(f"  Rate limited, waiting {wait}s...")
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("Embedding failed after retries")


def setup_schema(session):
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (p:Package) REQUIRE p.name IS UNIQUE")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE")
    session.run("""
        CREATE VECTOR INDEX vuln_embeddings IF NOT EXISTS
        FOR (v:Vulnerability) ON (v.embedding)
        OPTIONS {indexConfig: {`vector.dimensions`: 3072, `vector.similarity_function`: 'cosine'}}
    """)


def load_packages(packages: dict):
    print("Loading packages and DEPENDS_ON relationships...")
    for pkg, info in packages.items():
        with driver.session() as s:
            s.run(
                "MERGE (p:Package {name: $name}) SET p.version = $version, p.summary = $summary",
                name=info["name"], version=info["version"], summary=info["summary"],
            )
    for pkg, info in packages.items():
        for dep in info["requires"]:
            if dep in packages:
                with driver.session() as s:
                    s.run(
                        "MATCH (a:Package {name: $from}), (b:Package {name: $to}) MERGE (a)-[:DEPENDS_ON]->(b)",
                        **{"from": info["name"], "to": dep},
                    )


def load_vulnerabilities(vulnerabilities: dict):
    print("Loading vulnerabilities + embeddings...")
    # Get already-loaded vuln IDs to resume safely
    with driver.session() as s:
        existing = {r["id"] for r in s.run("MATCH (v:Vulnerability) WHERE v.embedding IS NOT NULL RETURN v.id AS id")}
    print(f"  Skipping {len(existing)} already-embedded vulns...")
    total = sum(len(v) for v in vulnerabilities.values())
    done = 0
    for pkg, vulns in vulnerabilities.items():
        for v in vulns:
            done += 1
            if v["id"] in existing:
                continue
            text = f"{v['id']}: {v['summary']}"
            embedding = get_embedding(text)
            with driver.session() as s:
                s.run(
                    """
                    MERGE (v:Vulnerability {id: $id})
                    SET v.summary = $summary,
                        v.severity = $severity,
                        v.published = $published,
                        v.embedding = $embedding
                    WITH v
                    MATCH (p:Package {name: $pkg})
                    MERGE (p)-[:HAS_VULNERABILITY]->(v)
                    """,
                    id=v["id"],
                    summary=v["summary"],
                    severity=v["severity"],
                    published=v["published"],
                    embedding=embedding,
                    pkg=pkg,
                )
            if done % 50 == 0:
                print(f"  {done}/{total} vulns processed...")


def main():
    packages = json.loads((DATA_DIR / "packages.json").read_text())
    vulnerabilities = json.loads((DATA_DIR / "vulnerabilities.json").read_text())

    print(f"Loading {len(packages)} packages, {sum(len(v) for v in vulnerabilities.values())} vulns...")
    with driver.session() as session:
        setup_schema(session)
    load_packages(packages)
    load_vulnerabilities(vulnerabilities)

    print("Done! Graph loaded into Neo4j Aura.")
    driver.close()


if __name__ == "__main__":
    main()

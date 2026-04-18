"""
Load PyPI dependency graph + OSV vulnerabilities into Neo4j Aura.
Run fetch_data.py first to populate data/.
"""

import json
import os
from pathlib import Path
from dotenv import load_dotenv
from neo4j import GraphDatabase
from neo4j_graphrag.embeddings import VertexAIEmbeddings
import vertexai

load_dotenv()

vertexai.init(
    project=os.environ["GOOGLE_CLOUD_PROJECT"],
    location=os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1"),
)

DATA_DIR = Path(__file__).parent.parent / "data"

driver = GraphDatabase.driver(
    os.environ["NEO4J_URI"],
    auth=(os.environ["NEO4J_USERNAME"], os.environ["NEO4J_PASSWORD"]),
)
embedder = VertexAIEmbeddings(model="text-embedding-005")


def get_embedding(text: str) -> list[float]:
    return embedder.embed_query(text[:2000])


def setup_schema(session):
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (p:Package) REQUIRE p.name IS UNIQUE")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE")
    session.run("""
        CREATE VECTOR INDEX vuln_embeddings IF NOT EXISTS
        FOR (v:Vulnerability) ON (v.embedding)
        OPTIONS {indexConfig: {`vector.dimensions`: 768, `vector.similarity_function`: 'cosine'}}
    """)


def load_packages(session, packages: dict):
    print("Loading packages and DEPENDS_ON relationships...")
    for pkg, info in packages.items():
        session.run(
            """
            MERGE (p:Package {name: $name})
            SET p.version = $version, p.summary = $summary
            """,
            name=info["name"], version=info["version"], summary=info["summary"],
        )
    # Load edges separately (both nodes must exist first)
    for pkg, info in packages.items():
        for dep in info["requires"]:
            if dep in packages:
                session.run(
                    """
                    MATCH (a:Package {name: $from}), (b:Package {name: $to})
                    MERGE (a)-[:DEPENDS_ON]->(b)
                    """,
                    **{"from": info["name"], "to": dep},
                )


def load_vulnerabilities(session, vulnerabilities: dict):
    print("Loading vulnerabilities + embeddings...")
    for pkg, vulns in vulnerabilities.items():
        for v in vulns:
            text = f"{v['id']}: {v['summary']}"
            embedding = get_embedding(text)
            session.run(
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


def main():
    packages = json.loads((DATA_DIR / "packages.json").read_text())
    vulnerabilities = json.loads((DATA_DIR / "vulnerabilities.json").read_text())

    print(f"Loading {len(packages)} packages, {sum(len(v) for v in vulnerabilities.values())} vulns...")
    with driver.session() as session:
        setup_schema(session)
        load_packages(session, packages)
        load_vulnerabilities(session, vulnerabilities)

    print("Done! Graph loaded into Neo4j Aura.")
    driver.close()


if __name__ == "__main__":
    main()

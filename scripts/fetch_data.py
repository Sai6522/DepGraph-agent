"""
Fetch PyPI dependency graph + OSV vulnerabilities.
Outputs: data/packages.json, data/vulnerabilities.json

Sources (both free, no auth):
  - PyPI JSON API:  https://pypi.org/pypi/<pkg>/json
  - OSV API:        https://api.osv.dev/v1/query
"""

import json
import time
from pathlib import Path
import requests

DATA_DIR = Path(__file__).parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)

# Seed packages — popular PyPI ecosystem, high vuln coverage
SEED_PACKAGES = [
    "flask", "django", "fastapi", "requests", "urllib3", "pillow",
    "numpy", "pandas", "sqlalchemy", "celery", "pydantic", "cryptography",
    "paramiko", "aiohttp", "werkzeug", "jinja2", "markupsafe", "setuptools",
    "pip", "wheel", "twisted", "scrapy", "httpx", "starlette", "uvicorn",
]


def fetch_pypi_deps(package: str) -> dict | None:
    """Return {name, version, requires} for latest release."""
    try:
        r = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        info = data["info"]
        requires = []
        for dep in (info.get("requires_dist") or []):
            # strip version constraints and extras → bare package name
            name = dep.split(";")[0].split(">=")[0].split("<=")[0] \
                      .split("!=")[0].split("==")[0].split(">")[0] \
                      .split("<")[0].split("[")[0].strip().lower()
            if name:
                requires.append(name)
        return {
            "name": info["name"].lower(),
            "version": info["version"],
            "summary": (info.get("summary") or "")[:200],
            "requires": list(set(requires)),
        }
    except Exception as e:
        print(f"  PyPI error for {package}: {e}")
        return None


def fetch_osv_vulns(package: str) -> list[dict]:
    """Return list of OSV vulnerabilities for a PyPI package."""
    try:
        r = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package, "ecosystem": "PyPI"}},
            timeout=10,
        )
        if r.status_code != 200:
            return []
        vulns = []
        for v in r.json().get("vulns", []):
            severity = "UNKNOWN"
            for s in v.get("severity", []):
                if s.get("type") == "CVSS_V3":
                    score = float(s["score"].split("/")[0].replace("CVSS:3.1/AV:", "").split(":")[0] or 0)
                    # parse CVSS base score from database_specific if available
                    break
            # simpler: use database_specific.severity if present
            db = v.get("database_specific", {})
            severity = db.get("severity", "UNKNOWN").upper()

            affected_versions = []
            for a in v.get("affected", []):
                for r_range in a.get("ranges", []):
                    for evt in r_range.get("events", []):
                        if "introduced" in evt:
                            affected_versions.append(evt["introduced"])

            vulns.append({
                "id": v["id"],
                "summary": (v.get("summary") or v.get("details") or "")[:300],
                "severity": severity,
                "affected_versions": affected_versions[:5],
                "published": v.get("published", ""),
            })
        return vulns
    except Exception as e:
        print(f"  OSV error for {package}: {e}")
        return []


def main():
    packages = {}
    vulnerabilities = {}

    # Collect deps up to 1 hop from seeds (keeps graph manageable)
    to_fetch = set(SEED_PACKAGES)
    fetched = set()

    print(f"Fetching {len(to_fetch)} seed packages + their direct deps...")
    while to_fetch:
        pkg = to_fetch.pop()
        if pkg in fetched:
            continue
        fetched.add(pkg)

        print(f"  PyPI: {pkg}")
        info = fetch_pypi_deps(pkg)
        if not info:
            continue
        packages[pkg] = info

        # Add direct deps to fetch queue (1 hop only)
        if pkg in SEED_PACKAGES:
            for dep in info["requires"]:
                if dep not in fetched:
                    to_fetch.add(dep)

        time.sleep(0.1)  # be polite to PyPI

    print(f"\nFetched {len(packages)} packages. Now fetching OSV vulnerabilities...")
    for pkg in list(packages.keys()):
        vulns = fetch_osv_vulns(pkg)
        if vulns:
            print(f"  {pkg}: {len(vulns)} vulns")
            vulnerabilities[pkg] = vulns
        time.sleep(0.15)

    # Save
    (DATA_DIR / "packages.json").write_text(json.dumps(packages, indent=2))
    (DATA_DIR / "vulnerabilities.json").write_text(json.dumps(vulnerabilities, indent=2))

    print(f"\nDone.")
    print(f"  Packages:        {len(packages)}")
    print(f"  Vulnerable pkgs: {len(vulnerabilities)}")
    print(f"  Total vulns:     {sum(len(v) for v in vulnerabilities.values())}")


if __name__ == "__main__":
    main()

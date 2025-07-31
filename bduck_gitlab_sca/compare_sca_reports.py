import json
from collections import defaultdict
from tabulate import tabulate

def load_report(path):
    with open(path, 'r') as f:
        return json.load(f)

def normalize_gitlab(report):
    deps = {}
    for dep in report.get("dependencies", []):
        name = dep.get("name")
        version = dep.get("version")
        key = f"{name}@{version}"
        deps[key] = {
            "vulnerabilities": dep.get("vulnerabilities", []),
            "licenses": dep.get("licenses", []),
            "source": "GitLab"
        }
    return deps

def normalize_blackduck(report):
    deps = {}
    for comp in report.get("components", []):
        name = comp.get("componentName")
        version = comp.get("componentVersionName")
        key = f"{name}@{version}"
        deps[key] = {
            "vulnerabilities": comp.get("vulnerabilities", []),
            "licenses": comp.get("licenses", []),
            "source": "BlackDuck"
        }
    return deps

def compare_reports(gitlab_deps, blackduck_deps):
    all_keys = set(gitlab_deps.keys()) | set(blackduck_deps.keys())
    comparison = []

    for key in sorted(all_keys):
        g = gitlab_deps.get(key, {})
        b = blackduck_deps.get(key, {})
        comparison.append({
            "Dependency": key,
            "GitLab Vulns": len(g.get("vulnerabilities", [])),
            "BlackDuck Vulns": len(b.get("vulnerabilities", [])),
            "GitLab Licenses": ", ".join(g.get("licenses", [])) if g else "N/A",
            "BlackDuck Licenses": ", ".join(b.get("licenses", [])) if b else "N/A",
            "Detected By": ", ".join(filter(None, [g.get("source"), b.get("source")]))
        })

    return comparison

def analyze_advantages(gitlab_deps, blackduck_deps):
    analysis = defaultdict(list)

    # Coverage
    analysis["Coverage"].append(f"GitLab detected {len(gitlab_deps)} dependencies")
    analysis["Coverage"].append(f"BlackDuck detected {len(blackduck_deps)} dependencies")

    # Vulnerability depth
    total_gitlab_vulns = sum(len(dep.get("vulnerabilities", [])) for dep in gitlab_deps.values())
    total_blackduck_vulns = sum(len(dep.get("vulnerabilities", [])) for dep in blackduck_deps.values())
    analysis["Vulnerability Detection"].append(f"GitLab found {total_gitlab_vulns} vulnerabilities")
    analysis["Vulnerability Detection"].append(f"BlackDuck found {total_blackduck_vulns} vulnerabilities")

    # License detection
    gitlab_licenses = {lic for dep in gitlab_deps.values() for lic in dep.get("licenses", [])}
    blackduck_licenses = {lic for dep in blackduck_deps.values() for lic in dep.get("licenses", [])}
    analysis["License Coverage"].append(f"GitLab identified {len(gitlab_licenses)} unique licenses")
    analysis["License Coverage"].append(f"BlackDuck identified {len(blackduck_licenses)} unique licenses")

    # Transitive dependencies
    analysis["Transitive Dependency Handling"].append("BlackDuck typically handles transitive dependencies better due to deeper SBOM analysis")
    analysis["Transitive Dependency Handling"].append("GitLab may miss some transitive packages depending on scanner configuration")

    # Metadata richness
    analysis["Metadata"].append("BlackDuck provides more detailed metadata including CVSS scores, remediation guidance, and policy violations")
    analysis["Metadata"].append("GitLab focuses on pipeline integration and basic vulnerability info")

    return analysis

def main():
    gitlab_path = "gitlab_report.json"
    blackduck_path = "blackduck_report.json"

    gitlab_deps = normalize_gitlab(load_report(gitlab_path))
    blackduck_deps = normalize_blackduck(load_report(blackduck_path))

    comparison = compare_reports(gitlab_deps, blackduck_deps)
    print("\n📊 Dependency Comparison:\n")
    print(tabulate(comparison, headers="keys", tablefmt="grid"))

    analysis = analyze_advantages(gitlab_deps, blackduck_deps)
    print("\n🧠 Detailed Analysis:\n")
    for section, points in analysis.items():
        print(f"🔹 {section}:")
        for point in points:
            print(f"   - {point}")
        print()

if __name__ == "__main__":
    main()

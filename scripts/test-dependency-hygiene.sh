#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
PROJECT_VERSION="$("${SCRIPT_DIR}/print-project-version.sh")" \
  || { echo "TEST FAILURE: cannot resolve the Maven project version" >&2; exit 1; }
PROJECT_VERSION="${PROJECT_VERSION#version=}"
DEFAULT_JAR="${PROJECT_DIR}/target/veloauth-${PROJECT_VERSION}.jar"
DEFAULT_SBOM="${PROJECT_DIR}/target/veloauth-${PROJECT_VERSION}.cdx.json"
JAR_PATH="${DEFAULT_JAR}"
SBOM_PATH="${DEFAULT_SBOM}"

fail() {
  echo "TEST FAILURE: $1" >&2
  exit 1
}

if [[ "${1:-}" == "--jar-only" ]]; then
  [[ $# -eq 2 ]] || fail "usage: $0 --jar-only /absolute/plugin.jar"
  JAR_PATH="$2"
  SBOM_PATH=""
elif [[ $# -gt 0 ]]; then
  [[ $# -eq 2 ]] || fail "usage: $0 [/absolute/plugin.jar /absolute/sbom.json]"
  JAR_PATH="$1"
  SBOM_PATH="$2"
fi

[[ "${JAR_PATH}" == /* ]] || fail "JAR path must be absolute"
[[ -f "${JAR_PATH}" ]] || fail "shaded JAR is missing: ${JAR_PATH}"
if [[ -n "${SBOM_PATH}" ]]; then
  [[ "${SBOM_PATH}" == /* ]] || fail "SBOM path must be absolute"
  [[ -f "${SBOM_PATH}" ]] || fail "CycloneDX SBOM is missing: ${SBOM_PATH}"
fi

python3 - "${PROJECT_DIR}/pom.xml" \
  "${PROJECT_DIR}/.github/workflows/build-and-release.yml" \
  "${PROJECT_DIR}/README.md" "${JAR_PATH}" "${SBOM_PATH}" "${PROJECT_VERSION}" <<'PY'
import json
import pathlib
import sys
import xml.etree.ElementTree as ET
import zipfile

pom_path, workflow_path, readme_path, jar_path = map(pathlib.Path, sys.argv[1:5])
sbom_path = pathlib.Path(sys.argv[5]) if sys.argv[5] else None
project_version = sys.argv[6]


def fail(message: str) -> None:
    raise SystemExit(f"TEST FAILURE: {message}")


root = ET.parse(pom_path).getroot()
namespace = root.tag.rpartition("}")[0] + "}"


def text(element: ET.Element, child: str, default: str = "") -> str:
    return (element.findtext(f"{namespace}{child}") or default).strip()


dependencies = {}
for dependency in root.findall(f"{namespace}dependencies/{namespace}dependency"):
    coordinate = f"{text(dependency, 'groupId')}:{text(dependency, 'artifactId')}"
    dependencies[coordinate] = (text(dependency, "version"), text(dependency, "scope", "compile"))

required_dependencies = {
    "org.slf4j:slf4j-api": ("2.0.17", "provided"),
    "jakarta.inject:jakarta.inject-api": ("2.0.1", "provided"),
    "net.kyori:adventure-api": ("4.26.1", "provided"),
    "net.kyori:adventure-key": ("4.26.1", "provided"),
    "net.kyori:adventure-text-serializer-gson": ("4.26.1", "provided"),
    "net.kyori:adventure-text-serializer-legacy": ("4.26.1", "provided"),
    "net.kyori:adventure-text-serializer-plain": ("4.26.1", "provided"),
    "com.google.code.gson:gson": ("2.13.2", "provided"),
    "org.spongepowered:configurate-core": ("4.2.0", "provided"),
    "org.spongepowered:configurate-yaml": ("4.2.0", "provided"),
    "io.netty:netty-common": ("${embedded.netty.version}", "provided"),
    "io.netty:netty-buffer": ("${embedded.netty.version}", "provided"),
    "io.netty:netty-transport": ("${embedded.netty.version}", "provided"),
    "io.netty:netty-codec-base": ("${embedded.netty.version}", "provided"),
    "io.netty:netty-handler": ("${embedded.netty.version}", "provided"),
    "org.bstats:bstats-base": ("3.2.1", "compile"),
    "org.cloudburstmc.math:immutable": ("2.0", "compile"),
    "org.junit.jupiter:junit-jupiter-api": ("5.12.0", "test"),
    "org.junit.jupiter:junit-jupiter-params": ("5.12.0", "test"),
    "org.junit.jupiter:junit-jupiter-engine": ("5.12.0", "test"),
    "org.slf4j:slf4j-simple": ("2.0.17", "test"),
}
for coordinate, expected in required_dependencies.items():
    if dependencies.get(coordinate) != expected:
        fail(f"direct dependency {coordinate} must be exactly {expected}, found {dependencies.get(coordinate)}")

for forbidden in ("io.netty:netty-resolver", "io.netty:netty-codec", "org.junit.jupiter:junit-jupiter"):
    if forbidden in dependencies:
        fail(f"redundant aggregator/direct dependency remains: {forbidden}")

plugins = {}
for plugin in root.findall(f"{namespace}build/{namespace}plugins/{namespace}plugin"):
    plugins[f"{text(plugin, 'groupId')}:{text(plugin, 'artifactId')}"] = plugin

dependency_plugin = plugins.get("org.apache.maven.plugins:maven-dependency-plugin")
if dependency_plugin is None or text(dependency_plugin, "version") != "3.11.0":
    fail("maven-dependency-plugin must be pinned to 3.11.0")
analysis = dependency_plugin.find(f"{namespace}executions/{namespace}execution")
if analysis is None or text(analysis, "phase") != "verify":
    fail("strict dependency analysis must run in verify")
if [goal.text.strip() for goal in analysis.findall(f"{namespace}goals/{namespace}goal")] != ["analyze-only"]:
    fail("strict dependency analysis must use only analyze-only")
configuration = dependency_plugin.find(f"{namespace}configuration")
if configuration is None or text(configuration, "failOnWarning") != "true" \
        or text(configuration, "ignoreNonCompile") != "false":
    fail("dependency analysis must fail on warnings and inspect non-compile scopes")
ignored = {
    (entry.text or "").strip()
    for entry in configuration.findall(
        f"{namespace}ignoredUnusedDeclaredDependencies/{namespace}ignoredUnusedDeclaredDependency"
    )
}
expected_ignored = {
    "com.mysql:mysql-connector-j",
    "org.postgresql:postgresql",
    "com.h2database:h2",
    "org.xerial:sqlite-jdbc",
    "io.netty:netty-handler",
    "org.junit.jupiter:junit-jupiter-engine",
}
if ignored != expected_ignored:
    fail(f"runtime/SPI ignore set must be exact; found {sorted(ignored)}")

cyclonedx = plugins.get("org.cyclonedx:cyclonedx-maven-plugin")
if cyclonedx is None or text(cyclonedx, "version") != "2.9.3":
    fail("CycloneDX Maven plugin must be pinned to 2.9.3")
execution = cyclonedx.find(f"{namespace}executions/{namespace}execution")
if execution is None or text(execution, "phase") != "package":
    fail("CycloneDX SBOM must be generated in package")
if [goal.text.strip() for goal in execution.findall(f"{namespace}goals/{namespace}goal")] != ["makeBom"]:
    fail("single-module build must use CycloneDX makeBom")
configuration = cyclonedx.find(f"{namespace}configuration")
expected_configuration = {
    "schemaVersion": "1.6",
    "outputFormat": "json",
    "outputName": "${project.artifactId}-${project.version}.cdx",
    "includeCompileScope": "true",
    "includeProvidedScope": "true",
    "includeRuntimeScope": "true",
    "includeSystemScope": "false",
    "includeTestScope": "false",
}
for key, expected in expected_configuration.items():
    if configuration is None or text(configuration, key) != expected:
        fail(f"CycloneDX {key} must be {expected}")

workflow = workflow_path.read_text(encoding="utf-8")
workflow_fragments = (
    "schedule:\n    - cron:",
    "dependency-review:\n    if: ${{ github.event_name == 'pull_request' }}",
    "actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294 # v5.0.0",
    "dependency-inventory:\n    if: ${{ github.event_name == 'push' || github.event_name == 'schedule' }}",
    "name: veloauth-osv-input-${{ github.sha }}",
    "osv-scan:\n    needs: dependency-inventory\n    if: ${{ github.event_name == 'push' || github.event_name == 'schedule' }}",
    "google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@8deb546fdb875b9996d27d4950be7312dac076a1 # v2.5.0",
    "download-artifact: veloauth-osv-input-${{ github.sha }}",
    "--no-resolve\n        --lockfile=pom.xml\n"
    "        --lockfile=veloauth-${{ needs.dependency-inventory.outputs.version }}.cdx.json",
    "needs: [candidate, osv-scan]",
    "needs.osv-scan.result == 'success'",
)
for fragment in workflow_fragments:
    if fragment not in workflow:
        fail(f"workflow contract is missing: {fragment}")
for forbidden in ("allow-ghsas:", "allow-dependencies:", "osv-scanner.toml"):
    if forbidden in workflow:
        fail(f"unowned vulnerability allowlist is forbidden: {forbidden}")

readme = readme_path.read_text(encoding="utf-8")
for evidence in (
    "Maven Dependency Plugin 3.11.0",
    "CycloneDX Maven Plugin 2.9.3",
    "Dependency Review v5.0.0",
    "OSV-Scanner v2.5.0",
    "advisory ID, reason, owner and expiry date",
    "There are no vulnerability allowlists",
):
    if evidence not in readme:
        fail(f"dependency policy evidence is missing from README: {evidence}")

with zipfile.ZipFile(jar_path) as jar:
    names = set(jar.namelist())
    required_entries = {
        "META-INF/services/java.sql.Driver",
        "com/mysql/cj/jdbc/Driver.class",
        "org/postgresql/Driver.class",
        "org/h2/Driver.class",
        "org/sqlite/JDBC.class",
        "net/rafalohaki/veloauth/libs/bstats/charts/CustomChart.class",
        "net/rafalohaki/veloauth/libs/cloudburst/math/vector/Vector3i.class",
        "net/rafalohaki/veloauth/libs/mcprotocollib/network/server/NetworkServer.class",
        "net/rafalohaki/veloauth/libs/ormlite/jdbc/JdbcConnectionSource.class",
    }
    missing = required_entries - names
    if missing:
        fail(f"shaded JAR is missing required runtime entries: {sorted(missing)}")

    def logical_class_path(name: str) -> str:
        parts = name.split("/")
        if len(parts) > 3 and parts[:2] == ["META-INF", "versions"] and parts[2].isdigit():
            return "/".join(parts[3:])
        return name

    allowed_class_prefixes = (
        "net/rafalohaki/veloauth/",
        "com/mysql/",
        "org/postgresql/",
        "org/h2/",
        "org/sqlite/",
    )

    def is_allowed_class(name: str) -> bool:
        return logical_class_path(name).startswith(allowed_class_prefixes)

    synthetic_forbidden_classes = (
        "META-INF/versions/21/io/netty/channel/Channel.class",
        "META-INF/versions/17/com/fasterxml/jackson/core/JsonFactory.class",
        "example/unowned/Foreign.class",
    )
    if any(is_allowed_class(name) for name in synthetic_forbidden_classes):
        fail("logical shaded inventory fixture accepted an unowned synthetic class")

    unowned_classes = sorted(
        name for name in names
        if name.endswith(".class")
        and not is_allowed_class(name)
    )
    if unowned_classes:
        fail(f"shaded JAR contains classes outside the exact logical allowlist: {unowned_classes[:20]}")

    forbidden_prefixes = (
        "org/slf4j/",
        "jakarta/inject/",
        "net/kyori/adventure/",
        "com/google/gson/",
        "io/netty/",
        "org/spongepowered/configurate/",
        "org/yaml/snakeyaml/",
        "com/fasterxml/jackson/",
    )
    leaked = sorted(
        name for name in names
        if logical_class_path(name).startswith(forbidden_prefixes)
    )
    if leaked:
        fail(f"proxy-provided classes leaked into shaded JAR: {leaked[:20]}")
    obsolete_private_json_yaml = sorted(
        name for name in names
        if logical_class_path(name).startswith((
            "net/rafalohaki/veloauth/libs/jackson/",
            "net/rafalohaki/veloauth/libs/snakeyaml/",
        ))
    )
    if obsolete_private_json_yaml:
        fail(f"obsolete private JSON/YAML runtime remains shaded: {obsolete_private_json_yaml[:20]}")
    providers = {
        line.strip()
        for line in jar.read("META-INF/services/java.sql.Driver").decode("utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    expected_providers = {"com.mysql.cj.jdbc.Driver", "org.postgresql.Driver", "org.h2.Driver", "org.sqlite.JDBC"}
    if providers != expected_providers:
        fail(f"JDBC SPI providers must be exact, found {sorted(providers)}")

if sbom_path:
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6":
        fail("SBOM must be CycloneDX schema 1.6 JSON")
    metadata_component = sbom.get("metadata", {}).get("component", {})
    if metadata_component.get("name") != "veloauth" \
            or metadata_component.get("version") != project_version:
        fail(f"SBOM metadata must identify VeloAuth {project_version}")
    components = {
        (component.get("group"), component.get("name"), component.get("version"))
        for component in sbom.get("components", [])
    }
    required_components = {
        ("org.bstats", "bstats-base", "3.2.1"),
        ("org.spongepowered", "configurate-core", "4.2.0"),
        ("org.spongepowered", "configurate-yaml", "4.2.0"),
        ("org.cloudburstmc.math", "immutable", "2.0"),
        ("org.slf4j", "slf4j-api", "2.0.17"),
        ("jakarta.inject", "jakarta.inject-api", "2.0.1"),
        ("net.kyori", "adventure-api", "4.26.1"),
        ("net.kyori", "adventure-key", "4.26.1"),
        ("net.kyori", "adventure-text-serializer-gson", "4.26.1"),
        ("net.kyori", "adventure-text-serializer-legacy", "4.26.1"),
        ("net.kyori", "adventure-text-serializer-plain", "4.26.1"),
        ("com.google.code.gson", "gson", "2.13.2"),
        ("io.netty", "netty-codec-base", "4.2.15.Final"),
        ("com.mysql", "mysql-connector-j", "9.5.0"),
        ("org.postgresql", "postgresql", "42.7.13"),
        ("com.h2database", "h2", "2.4.240"),
        ("org.xerial", "sqlite-jdbc", "3.51.1.0"),
    }
    missing_components = required_components - components
    if missing_components:
        fail(f"SBOM is missing required components: {sorted(missing_components)}")
    if any(group == "org.junit.jupiter" for group, _, _ in components):
        fail("test-only JUnit components must not be shipped in the production SBOM")

print("Dependency declaration, scanner, SBOM, shaded inventory, and JDBC SPI fixtures passed")
PY

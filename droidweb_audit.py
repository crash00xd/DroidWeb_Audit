#!/usr/bin/env python3
"""
DroidWeb Audit - static APK triage focused on Android WebView security indicators.

This tool does not execute APK code and does not confirm vulnerabilities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

TOOL_NAME = "DroidWeb Audit"
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"

LOG = logging.getLogger("droidweb_audit")

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Rules intentionally distinguish API usage from risky configuration indicators.
SINK_RULES = [
    {
        "id": "WV-API-001", "class": "Landroid/webkit/WebView;",
        "method": "addJavascriptInterface", "title": "JavaScript interface registration",
        "category": "webview_bridge", "severity": "HIGH", "confidence": "MEDIUM",
        "why": "A Java object is exposed to JavaScript through a WebView bridge. Risk depends on the exposed methods, Android versions, and the origin/content loaded.",
        "validation": "Inspect the exposed object and its public methods; determine whether untrusted content can reach the WebView; validate origin restrictions and reachable bridge methods."
    },
    {
        "id": "WV-API-002", "class": "Landroid/webkit/WebView;",
        "method": "setWebContentsDebuggingEnabled", "title": "WebView debugging control",
        "category": "debugging", "severity": "MEDIUM", "confidence": "MEDIUM",
        "why": "The application references the WebView debugging toggle. The call argument and runtime state are not inferred by this static indicator.",
        "validation": "Determine whether the call enables debugging in release builds and whether the WebView exposes sensitive authenticated content."
    },
    {
        "id": "WV-API-003", "class": "Landroid/webkit/WebView;",
        "method": "evaluateJavascript", "title": "JavaScript execution in WebView",
        "category": "javascript_execution", "severity": "MEDIUM", "confidence": "LOW",
        "why": "The application invokes JavaScript in a WebView. Risk depends on how scripts and arguments are constructed and whether untrusted input reaches them.",
        "validation": "Trace arguments to evaluateJavascript and test whether untrusted data can influence executable script content."
    },
    {
        "id": "WV-API-004", "class": "Landroid/webkit/WebView;",
        "method": "loadUrl", "title": "WebView URL loading",
        "category": "navigation", "severity": "INFO", "confidence": "LOW",
        "why": "The application loads a URL in a WebView. This is common behavior and is not a vulnerability by itself.",
        "validation": "Trace the URL source and verify scheme, host, redirect, and navigation allowlists."
    },
    {
        "id": "WV-API-005", "class": "Landroid/webkit/WebViewClient;",
        "method": "shouldOverrideUrlLoading", "title": "WebView navigation callback",
        "category": "navigation_control", "severity": "INFO", "confidence": "LOW",
        "why": "A WebView navigation callback is referenced or implemented. Its presence does not establish that navigation is safely restricted.",
        "validation": "Review the callback implementation and confirm that untrusted schemes, hosts, and redirects are rejected."
    },
    {
        "id": "WV-API-006", "class": "Landroid/webkit/WebSettings;",
        "method": "setJavaScriptEnabled", "title": "JavaScript setting",
        "category": "javascript", "severity": "MEDIUM", "confidence": "LOW",
        "why": "The application changes the JavaScript setting. JavaScript is frequently required by legitimate applications; risk depends on content trust and other controls.",
        "validation": "Determine the configured boolean value and whether untrusted or attacker-controlled content can be loaded."
    },
    {
        "id": "WV-API-007", "class": "Landroid/webkit/WebSettings;",
        "method": "setAllowFileAccess", "title": "WebView file access setting",
        "category": "file_access", "severity": "MEDIUM", "confidence": "LOW",
        "why": "The application changes WebView file access. The static call alone does not reveal the configured value.",
        "validation": "Resolve the argument value and assess whether local files or untrusted content can be accessed."
    },
    {
        "id": "WV-API-008", "class": "Landroid/webkit/WebSettings;",
        "method": "setAllowFileAccessFromFileURLs", "title": "File-origin access setting",
        "category": "file_access", "severity": "HIGH", "confidence": "MEDIUM",
        "why": "The application references a setting that can permit file-origin pages to access other local files when enabled.",
        "validation": "Resolve the configured value and assess whether attacker-controlled file-origin content can be loaded."
    },
    {
        "id": "WV-API-009", "class": "Landroid/webkit/WebSettings;",
        "method": "setAllowUniversalAccessFromFileURLs", "title": "Universal access from file URLs",
        "category": "file_access", "severity": "HIGH", "confidence": "MEDIUM",
        "why": "The application references a setting that can allow file-origin content to make cross-origin requests when enabled.",
        "validation": "Resolve the configured value and determine whether untrusted file-origin content can reach sensitive origins or data."
    },
    {
        "id": "WV-API-010", "class": "Landroid/webkit/WebSettings;",
        "method": "setMixedContentMode", "title": "WebView mixed-content policy",
        "category": "transport_security", "severity": "MEDIUM", "confidence": "LOW",
        "why": "The application changes the mixed-content policy. The selected mode is not inferred by this finding.",
        "validation": "Resolve the selected mode and assess whether HTTPS pages can load active or passive HTTP content."
    },
]

STRING_RULES = [
    ("WV-STR-001", "javascript:", "JavaScript URL scheme", "MEDIUM",
     "A JavaScript URL string is present. It may be inert, test data, or dynamically assembled."),
    ("WV-STR-002", "file://", "Local file URL scheme", "MEDIUM",
     "A file URL string is present. Presence does not prove that a WebView loads it."),
    ("WV-STR-003", "setallowuniversalaccessfromfileurls", "Universal file-origin access API string", "HIGH",
     "A sensitive WebSettings API name is present as a string; this does not prove invocation or an enabled setting."),
    ("WV-STR-004", "setallowfileaccessfromfileurls", "File-origin access API string", "HIGH",
     "A sensitive WebSettings API name is present as a string; this does not prove invocation or an enabled setting."),
    ("WV-STR-005", "setallowfileaccess", "File access API string", "MEDIUM",
     "A WebSettings file-access API name is present as a string; this does not prove invocation or an enabled setting."),
    ("WV-STR-006", "android.webkit", "Android WebKit namespace string", "INFO",
     "A WebKit namespace string is present and may be useful for locating WebView-related code."),
]

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    evidence_type: str
    evidence: dict[str, Any]
    rationale: str
    manual_validation: str
    status: str = "REQUIRES_MANUAL_VALIDATION"


@dataclass
class AnalysisResult:
    metadata: dict[str, Any]
    manifest: dict[str, Any]
    findings: list[dict[str, Any]]
    risk_summary: dict[str, Any]
    errors: list[str] = field(default_factory=list)


def _safe_call(obj: Any, method: str, default: Any = None, *args: Any) -> Any:
    try:
        fn = getattr(obj, method)
        return fn(*args)
    except Exception:
        return default


def _method_parts(method_obj: Any) -> tuple[str, str, str]:
    """Extract class, method name and descriptor from Androguard method wrappers."""
    raw = _safe_call(method_obj, "get_method", method_obj)
    class_name = (
        getattr(raw, "class_name", None)
        or _safe_call(raw, "get_class_name", "")
        or getattr(method_obj, "class_name", "")
        or ""
    )
    method_name = (
        getattr(raw, "name", None)
        or _safe_call(raw, "get_name", "")
        or getattr(method_obj, "name", "")
        or ""
    )
    descriptor = (
        getattr(raw, "descriptor", None)
        or _safe_call(raw, "get_descriptor", "")
        or getattr(method_obj, "descriptor", "")
        or ""
    )
    return str(class_name), str(method_name), str(descriptor)


def _caller_evidence(class_analysis: Any, caller: Any, offset: Any) -> dict[str, Any]:
    class_name = getattr(class_analysis, "name", "") or _safe_call(class_analysis, "get_name", "")
    caller_class, caller_name, caller_descriptor = _method_parts(caller)
    return {
        "class": str(class_name or caller_class),
        "method": caller_name,
        "descriptor": caller_descriptor,
        "offset": int(offset) if isinstance(offset, int) else None,
    }


def _xml_attr(element: Any, name: str) -> str | None:
    if element is None:
        return None
    value = element.get(ANDROID_NS + name)
    return str(value) if value is not None else None


def _as_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() in {"true", "1"}


def collect_manifest_info(apk_obj: Any) -> dict[str, Any]:
    """Collect manifest metadata and component export/security-relevant attributes."""
    root = _safe_call(apk_obj, "get_android_manifest_xml")
    manifest_node = root if getattr(root, "tag", "").endswith("manifest") else None
    application = None
    if root is not None:
        application = root.find("application")
        if application is None:
            application = root.find("{*}application")

    components: list[dict[str, Any]] = []
    if application is not None:
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for node in application.findall(tag):
                components.append({
                    "type": tag,
                    "name": _xml_attr(node, "name"),
                    "exported": _as_bool(_xml_attr(node, "exported")),
                    "permission": _xml_attr(node, "permission"),
                    "enabled": _as_bool(_xml_attr(node, "enabled")),
                })

    permissions = _safe_call(apk_obj, "get_permissions", []) or []
    activities = _safe_call(apk_obj, "get_activities", []) or []
    services = _safe_call(apk_obj, "get_services", []) or []
    receivers = _safe_call(apk_obj, "get_receivers", []) or []
    providers = _safe_call(apk_obj, "get_providers", []) or []

    app_label = _safe_call(apk_obj, "get_app_name")
    package_name = _safe_call(apk_obj, "get_package")
    manifest_data = {
        "package": package_name,
        "application_name": app_label,
        "version_name": _safe_call(apk_obj, "get_androidversion_name"),
        "version_code": _safe_call(apk_obj, "get_androidversion_code"),
        "min_sdk": _safe_call(apk_obj, "get_min_sdk_version"),
        "target_sdk": _safe_call(apk_obj, "get_target_sdk_version"),
        "permissions": sorted(str(x) for x in permissions),
        "activities": sorted(str(x) for x in activities),
        "services": sorted(str(x) for x in services),
        "receivers": sorted(str(x) for x in receivers),
        "providers": sorted(str(x) for x in providers),
        "components": sorted(components, key=lambda x: (x["type"], x["name"] or "")),
        "application_flags": {
            "debuggable": _as_bool(_xml_attr(application, "debuggable")),
            "allow_backup": _as_bool(_xml_attr(application, "allowBackup")),
            "uses_cleartext_traffic": _as_bool(_xml_attr(application, "usesCleartextTraffic")),
            "network_security_config": _xml_attr(application, "networkSecurityConfig"),
        },
        "manifest_package_attribute": manifest_node.get("package") if manifest_node is not None else package_name,
    }
    return manifest_data


def find_sink_calls(dx: Any) -> list[Finding]:
    """Find references to selected Android WebView APIs and capture XREF callers."""
    findings: list[Finding] = []
    targets = {(r["class"], r["method"]): r for r in SINK_RULES}

    try:
        method_analyses = list(dx.get_methods())
    except Exception as exc:
        raise RuntimeError(f"Não foi possível enumerar métodos do DEX: {exc}") from exc

    for method_analysis in method_analyses:
        class_name, method_name, descriptor = _method_parts(method_analysis)
        rule = targets.get((class_name, method_name))
        if not rule:
            continue

        xrefs = _safe_call(method_analysis, "get_xref_from", []) or []
        callers = []
        for item in xrefs:
            try:
                caller_class, caller_method, offset = item
                callers.append(_caller_evidence(caller_class, caller_method, offset))
            except (TypeError, ValueError):
                continue

        evidence = {
            "target_class": class_name,
            "target_method": method_name,
            "target_descriptor": descriptor,
            "callers": sorted(
                callers,
                key=lambda x: (x["class"], x["method"], x["offset"] or -1)
            ),
            "xref_count": len(callers),
        }
        findings.append(Finding(
            finding_id=rule["id"],
            rule_id=rule["id"],
            title=rule["title"],
            category=rule["category"],
            severity=rule["severity"],
            confidence=rule["confidence"],
            evidence_type="DEX_METHOD_REFERENCE",
            evidence=evidence,
            rationale=rule["why"],
            manual_validation=rule["validation"],
        ))

    # Also report app-defined shouldOverrideUrlLoading implementations. This is a
    # declaration heuristic; it does not assess the callback's implementation.
    for method_analysis in method_analyses:
        class_name, method_name, descriptor = _method_parts(method_analysis)
        if method_name != "shouldOverrideUrlLoading" or not class_name.startswith("L"):
            continue
        is_external = _safe_call(method_analysis, "is_external", False)
        if is_external:
            continue
        rule = next(r for r in SINK_RULES if r["id"] == "WV-API-005")
        findings.append(Finding(
            finding_id=rule["id"],
            rule_id=rule["id"],
            title=rule["title"],
            category=rule["category"],
            severity=rule["severity"],
            confidence="LOW",
            evidence_type="DEX_METHOD_DECLARATION",
            evidence={"class": class_name, "method": method_name, "descriptor": descriptor},
            rationale="A aplicação declara um método com o nome do callback de navegação do WebView. A implementação não foi avaliada.",
            manual_validation=rule["validation"],
        ))
    return findings


def find_strings_interest(dx: Any) -> list[Finding]:
    """Search DEX string analysis objects and include their reference locations."""
    findings: list[Finding] = []
    try:
        strings_analysis = dx.get_strings_analysis()
        iterable = strings_analysis.values()
    except Exception:
        iterable = _safe_call(dx, "get_strings", []) or []

    seen: set[tuple[str, str]] = set()
    for string_analysis in iterable:
        value = _safe_call(string_analysis, "get_value", None)
        if value is None:
            value = getattr(string_analysis, "value", None)
        if not isinstance(value, str):
            continue
        lowered = value.lower()
        for rule_id, needle, title, severity, rationale in STRING_RULES:
            if needle not in lowered:
                continue
            key = (rule_id, value)
            if key in seen:
                continue
            seen.add(key)
            refs = _safe_call(string_analysis, "get_xref_from", [], True) or []
            locations = []
            for item in refs:
                try:
                    caller_class, caller_method, offset = item
                    locations.append(_caller_evidence(caller_class, caller_method, offset))
                except (TypeError, ValueError):
                    try:
                        caller_class, caller_method = item
                        locations.append(_caller_evidence(caller_class, caller_method, None))
                    except (TypeError, ValueError):
                        continue
            findings.append(Finding(
                finding_id=rule_id,
                rule_id=rule_id,
                title=title,
                category="string_indicator",
                severity=severity,
                confidence="LOW",
                evidence_type="DEX_STRING",
                evidence={
                    "matched_pattern": needle,
                    "value": value[:500],
                    "value_truncated": len(value) > 500,
                    "references": sorted(locations, key=lambda x: (x["class"], x["method"], x["offset"] or -1)),
                },
                rationale=rationale,
                manual_validation="Localize a referência no código e confirme se a string participa de um fluxo executável relacionado a WebView.",
            ))
    return findings


def summarize_risk(findings: Iterable[Finding]) -> dict[str, Any]:
    items = list(findings)
    counts = {level: 0 for level in ("HIGH", "MEDIUM", "LOW", "INFO")}
    for finding in items:
        if finding.severity in counts:
            counts[finding.severity] += 1
    highest = next((level for level in ("HIGH", "MEDIUM", "LOW", "INFO") if counts[level]), "NONE")
    return {
        "highest_indicator": highest,
        "counts": counts,
        "total_indicators": len(items),
        "interpretation": (
            "Resumo heurístico de indicadores estáticos. Não representa severidade CVSS "
            "nem confirma vulnerabilidades; valide cada achado manualmente."
        ),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_apk(apk_path: Path) -> AnalysisResult:
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError as exc:
        raise RuntimeError(
            "Androguard não está instalado. Instale as dependências com: pip install -r requirements.txt"
        ) from exc

    try:
        apk_obj, _dex_objects, dx = AnalyzeAPK(str(apk_path))
    except Exception as exc:
        raise RuntimeError(f"Falha ao analisar o APK com Androguard: {exc}") from exc

    errors: list[str] = []
    try:
        manifest = collect_manifest_info(apk_obj)
    except Exception as exc:
        manifest = {}
        errors.append(f"Falha parcial ao coletar manifesto: {exc}")

    findings: list[Finding] = []
    try:
        findings.extend(find_sink_calls(dx))
    except Exception as exc:
        errors.append(f"Falha na análise de chamadas DEX: {exc}")
    try:
        findings.extend(find_strings_interest(dx))
    except Exception as exc:
        errors.append(f"Falha na análise de strings DEX: {exc}")

    # Stable deduplication: same rule and same evidence payload.
    unique: dict[str, Finding] = {}
    for finding in findings:
        key = json.dumps(asdict(finding), sort_keys=True, ensure_ascii=False)
        unique[key] = finding
    findings = sorted(
        unique.values(),
        key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.rule_id, json.dumps(x.evidence, sort_keys=True))
    )

    metadata = {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "input_file": apk_path.name,
        "file_size_bytes": apk_path.stat().st_size,
        "sha256": _sha256(apk_path),
        "analysis_type": "STATIC",
        "execution_performed": False,
        "androguard_version": _androguard_version(),
    }
    return AnalysisResult(
        metadata=metadata,
        manifest=manifest,
        findings=[asdict(x) for x in findings],
        risk_summary=summarize_risk(findings),
        errors=errors,
    )


def _androguard_version() -> str | None:
    try:
        from importlib.metadata import version
        return version("androguard")
    except Exception:
        return None


def render_text(result: AnalysisResult) -> str:
    lines = [
        f"{TOOL_NAME} v{TOOL_VERSION}",
        "=" * 72,
        f"APK: {result.metadata.get('input_file')}",
        f"SHA-256: {result.metadata.get('sha256')}",
        f"Pacote: {result.manifest.get('package') or 'não identificado'}",
        f"Analisado em: {result.metadata.get('analyzed_at')}",
        "",
        "RESUMO DE INDICADORES",
        "-" * 72,
        f"Maior nível heurístico: {result.risk_summary['highest_indicator']}",
        f"Total: {result.risk_summary['total_indicators']}",
    ]
    for level, count in result.risk_summary["counts"].items():
        lines.append(f"  {level}: {count}")
    lines += ["", "ACHADOS", "-" * 72]
    if not result.findings:
        lines.append("Nenhum indicador coberto pelas regras atuais foi identificado.")
    for index, finding in enumerate(result.findings, 1):
        lines += [
            f"[{index}] {finding['title']} ({finding['rule_id']})",
            f"    Severidade heurística: {finding['severity']} | Confiança: {finding['confidence']}",
            f"    Categoria: {finding['category']} | Evidência: {finding['evidence_type']}",
            f"    Justificativa: {finding['rationale']}",
            f"    Evidência: {json.dumps(finding['evidence'], ensure_ascii=False, sort_keys=True)}",
            f"    Validação manual: {finding['manual_validation']}",
            f"    Status: {finding['status']}",
            "",
        ]
    if result.errors:
        lines += ["ERROS PARCIAIS", "-" * 72]
        lines.extend(f"- {error}" for error in result.errors)
        lines.append("")
    lines += [
        "NOTA: indicadores estáticos não comprovam vulnerabilidades. "
        "A ausência de achados também não comprova segurança.",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="droidweb-audit",
        description="Análise estática de APK Android com foco em indicadores de segurança de WebView."
    )
    parser.add_argument("apk", help="Caminho do arquivo APK a analisar.")
    parser.add_argument("--json", action="store_true", help="Emite relatório JSON no stdout.")
    parser.add_argument("--out", help="Salva o relatório no caminho informado.")
    parser.add_argument(
        "--max-apk-size-mb", type=int, default=512,
        help="Tamanho máximo aceito para o APK em MiB (padrão: 512)."
    )
    parser.add_argument("--verbose", action="store_true", help="Exibe mensagens de diagnóstico no stderr.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    apk_path = Path(args.apk).expanduser()
    if not apk_path.exists():
        parser.error(f"arquivo não encontrado: {apk_path}")
    if not apk_path.is_file():
        parser.error(f"o caminho informado não é um arquivo: {apk_path}")
    if apk_path.suffix.lower() != ".apk":
        parser.error("a extensão do arquivo deve ser .apk")
    if not apk_path.stat().st_size:
        parser.error("o arquivo APK está vazio")
    if args.max_apk_size_mb < 1:
        parser.error("--max-apk-size-mb deve ser maior que zero")
    max_bytes = args.max_apk_size_mb * 1024 * 1024
    if apk_path.stat().st_size > max_bytes:
        parser.error(f"APK excede o limite de {args.max_apk_size_mb} MiB")

    try:
        result = analyze_apk(apk_path)
    except Exception as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2

    output = (
        json.dumps(asdict(result), indent=2, ensure_ascii=False, sort_keys=True)
        if args.json else render_text(result)
    )

    if args.out:
        out_path = Path(args.out).expanduser()
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"ERRO: não foi possível gravar {out_path}: {exc}", file=sys.stderr)
            return 3

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

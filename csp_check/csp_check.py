#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests",
#     "rich",
#     "tldextract",
# ]
# ///

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ---------------------------------------
# Knowledge base
# ---------------------------------------

T_HELP: Dict[str, Dict[str, str]] = {
    # Fetch directives
    "child-src": {"text": "Workers/iframes (deprecated in CSP3; use frame-src + worker-src).", "color": "yellow"},
    "connect-src": {"text": "Restricts URLs loaded via script interfaces.", "color": "white"},
    "default-src": {"text": "Fallback for other fetch directives.", "color": "white"},
    "font-src": {"text": "Valid sources for @font-face.", "color": "white"},
    "frame-src": {"text": "Valid sources for iframes.", "color": "white"},
    "img-src": {"text": "Valid sources of images/favicons.", "color": "white"},
    "manifest-src": {"text": "Valid sources for web app manifests.", "color": "white"},
    "media-src": {"text": "Valid sources for audio/video/track.", "color": "white"},
    "object-src": {"text": "Valid sources for <object>/<embed>.", "color": "white"},
    "prefetch-src": {"text": "Valid sources to prefetch/prerender.", "color": "white"},
    "script-src": {"text": "Valid sources for JavaScript.", "color": "white"},
    "style-src": {"text": "Valid sources for stylesheets.", "color": "white"},
    "webrtc-src": {"text": "Valid sources for WebRTC.", "color": "white"},
    "worker-src": {"text": "Valid sources for Worker/SharedWorker/ServiceWorker.", "color": "white"},
    # Document directives
    "base-uri": {"text": "Restricts URLs allowed in <base>.", "color": "white"},
    "plugin-types": {"text": "Legacy plugin resource types.", "color": "yellow"},
    "sandbox": {"text": "Enables a sandbox like the <iframe> attribute.", "color": "white"},
    "disown-opener": {"text": "Ensures a resource disowns its opener (legacy).", "color": "yellow"},
    # Navigation directives
    "form-action": {"text": "Restricts form action targets.", "color": "white"},
    "frame-ancestors": {"text": "Valid parents that may embed the page.", "color": "white"},
    "navigate-to": {"text": "Restricts where a document can navigate.", "color": "white"},
    # Reporting
    "report-uri": {"text": "Legacy violation report endpoint (prefer report-to).", "color": "yellow"},
    "report-to": {"text": "Reporting API group for CSP violations.", "color": "white"},
    # Other directives
    "block-all-mixed-content": {"text": "Disallow HTTP on HTTPS pages (legacy-ish).", "color": "yellow"},
    "referrer": {"text": "Deprecated. Use Referrer-Policy header.", "color": "yellow"},
    "require-sri-for": {"text": "Require SRI for scripts/styles.", "color": "white"},
    "upgrade-insecure-requests": {"text": "Rewrite insecure URLs to HTTPS.", "color": "white"},
    # Source expressions (examples + keywords)
    "*": {"text": "Wildcard; allows any origin (except some schemes).", "color": "dark_orange"},
    "'none'": {"text": "No sources allowed.", "color": "green"},
    "'self'": {"text": "Same origin (scheme/host/port).", "color": "green"},
    "data:": {"text": "Allow data: scheme (inline data).", "color": "yellow"},
    "blob:": {"text": "Allow blob: object URLs.", "color": "yellow"},
    "'unsafe-inline'": {"text": "Allow inline code/event handlers.", "color": "red"},
    "'unsafe-eval'": {"text": "Allow eval()/Function constructor.", "color": "red"},
    "'nonce-'": {"text": "Allow inline script/style with matching nonce.", "color": "green"},
    "'sha256-'": {"text": "Allow inline script/style matching the hash.", "color": "green"},
    # Example host patterns remain for docs but won't match real items:
    "domain.example.com": {"text": "Specific host.", "color": "white"},
    "*.example.com": {"text": "Any subdomain (wildcard).", "color": "dark_orange"},
    "https://cdn.com": {"text": "Specific HTTPS host.", "color": "white"},
    "https:": {"text": "Any HTTPS origin.", "color": "white"},
}

DEPRECATED_OR_LEGACY = {
    "referrer",
    "child-src",
    "plugin-types",
    "report-uri",
    "disown-opener",
    "block-all-mixed-content",
    "reflected-xss",
}

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0"

console = Console()

# ---------------------------------------
# Data structures
# ---------------------------------------


@dataclass
class SourceItem:
    raw: str
    normalized: str
    note: Optional[str] = None
    color: str = "white" 


@dataclass
class Policy:
    name: str
    items: List[SourceItem] = field(default_factory=list)
    is_deprecated: bool = False
    help_text: Optional[str] = None


@dataclass
class URLResult:
    url: str
    requested_url: str
    csp_raw: Optional[str]
    policies: List[Policy] = field(default_factory=list)
    deprecated_used: List[str] = field(default_factory=list)
    warnings: Dict[str, object] = field(default_factory=dict)
    error: Optional[str] = None


# ---------------------------------------
# Utilities
# ---------------------------------------


def normalize_url_maybe(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else "https://" + url


def parse_cookies(cookie_str: Optional[str]) -> Dict[str, str]:
    if not cookie_str:
        return {}
    jar: Dict[str, str] = {}
    for c in cookie_str.split(";"):
        c = c.strip()
        if not c:
            continue
        if "=" in c:
            k, v = c.split("=", 1)
            jar[k.strip()] = v.strip()
    return jar


def is_wildcard_token(token: str) -> bool:
    if token == "*":
        return True
    if "://" in token:
        host = urllib.parse.urlparse(token).netloc
    else:
        host = token
    return "*" in host


def pretty_csp(csp_raw: str) -> str:
    parts = [p.strip() for p in csp_raw.split(";") if p.strip()]
    if not parts:
        return ""
    return ";\n".join(f"{p}" for p in parts) + ";"


def highlight_csp_problems(csp_pretty: str, res: URLResult) -> str:
    """
    Surround matching problem items in the pretty-printed CSP with
    §R[...]R§ markers for LaTeX highlighting.
    Wildcard domains (e.g. *.example.com) are wrapped as a whole.
    """
    problem_items = set()

    if res.warnings.get("unsafe_inline"):
        problem_items.add("'unsafe-inline'")
    if res.warnings.get("unsafe_eval"):
        problem_items.add("'unsafe-eval'")
    if res.warnings.get("data_or_blob"):
        problem_items.update({"data:", "blob:"})
    if res.warnings.get("missing_https_and_upgrade"):
        for token in csp_pretty.replace(";", " ").split():
            if token.startswith("http://"):
                problem_items.add(token)

    if res.warnings.get("wildcard_sources"):
        for token in csp_pretty.replace(";", " ").split():
            if "*" in token:
                problem_items.add(token)

    highlighted = csp_pretty
    for item in sorted(problem_items, key=len, reverse=True):
        highlighted = highlighted.replace(item, f"§R[{item}]R§")

    return highlighted


def normalize_lang(lang: Optional[str]) -> str:
    if not lang:
        return "en"
    lang = lang.strip().lower()
    if lang in {"de", "german", "deutsch"}:
        return "de"
    return "en"


def parse_csp(url: str, cookies: Dict[str, str]) -> URLResult:
    requested_url = url
    url = normalize_url_maybe(url)

    try:
        resp = requests.get(
            url,
            cookies=cookies,
            allow_redirects=False,
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
    except Exception as e:
        return URLResult(url=url, requested_url=requested_url, csp_raw=None, error=f"Request failed: {e}")

    csp_header = resp.headers.get("Content-Security-Policy")
    if not csp_header:
        return URLResult(
            url=url, requested_url=requested_url, csp_raw=None, error="Content-Security-Policy header not found"
        )

    parts = [p.strip() for p in csp_header.split(";")]

    policies: List[Policy] = []
    deprecated_used: List[str] = []

    has_unsafe_inline = False
    has_unsafe_eval = False
    has_wildcard = False
    has_data_or_blob = False
    has_report_to = False
    has_upgrade_insecure = False
    has_explicit_https_source = False

    for part in parts:
        if not part:
            continue
        tokens = [t for t in part.split() if t]
        if not tokens:
            continue

        name, *values = tokens
        p_help = T_HELP.get(name, {}).get("text")
        is_depr = name in DEPRECATED_OR_LEGACY
        if is_depr:
            deprecated_used.append(name)

        if name == "report-to":
            has_report_to = True
        if name == "upgrade-insecure-requests":
            has_upgrade_insecure = True

        policy = Policy(name=name, is_deprecated=is_depr, help_text=p_help)

        for item in values:
            norm = item
            if item.startswith("'nonce-"):
                norm = "'nonce-'"
            elif item.startswith("'sha256-"):
                norm = "'sha256-'"

            note = T_HELP.get(norm, {}).get("text")

            if norm == "'unsafe-inline'":
                has_unsafe_inline = True
            if norm == "'unsafe-eval'":
                has_unsafe_eval = True
            if is_wildcard_token(item) or norm == "*":
                has_wildcard = True
            if norm in {"data:", "blob:"}:
                has_data_or_blob = True
            if item.startswith("https://") or norm == "https:":
                has_explicit_https_source = True

            # Coloring rules
            if is_wildcard_token(item) or norm in {"*", "data:", "blob:", "'unsafe-inline'", "'unsafe-eval'"}:
                if is_wildcard_token(item) or norm == "*":
                    color = "dark_orange"
                elif norm in {"'unsafe-inline'", "'unsafe-eval'"}:
                    color = "red"
                else:
                    color = "yellow"  # data:, blob:
            elif norm in {"'none'", "'self'"}:
                color = "blue"
            else:
                color = "white"

            policy.items.append(SourceItem(raw=item, normalized=norm, note=note, color=color))

        policies.append(policy)

    warnings_dict = {
        "deprecated_directives": sorted(set(deprecated_used)),
        "unsafe_inline": has_unsafe_inline,
        "unsafe_eval": has_unsafe_eval,
        "wildcard_sources": has_wildcard,
        "data_or_blob": has_data_or_blob,
        "missing_report_to": not has_report_to,
        "missing_https_and_upgrade": (not has_explicit_https_source) and (not has_upgrade_insecure),
    }

    return URLResult(
        url=url,
        requested_url=requested_url,
        csp_raw=csp_header,
        policies=policies,
        deprecated_used=sorted(set(deprecated_used)),
        warnings=warnings_dict, 
        error=None,
    )


# ---------------------------------------
# Renderers
# ---------------------------------------


class BaseRenderer:
    def render_many(self, results: List[URLResult]) -> str:
        raise NotImplementedError


class TextRenderer(BaseRenderer):
    def __init__(self, console: Optional[Console]):
        self.console = console

    def print_to_console(self, results: List[URLResult]) -> None:
        for res in results:
            header = Text.from_markup(f"[bold]{res.requested_url}[/bold] — Fetched: [cyan]{res.url}[/cyan]")
            self.console.print(Panel(header, expand=False, box=box.ROUNDED))

            if res.error:
                self.console.print(f"[red]Error:[/red] {res.error}")
                self.console.print()
                continue

            warn_lines = []
            if res.warnings.get("deprecated_directives"):
                warn_lines.append("Deprecated/legacy directives: " + ", ".join(res.warnings["deprecated_directives"]))
            if res.warnings.get("unsafe_inline"):
                warn_lines.append("Uses [red]'unsafe-inline'[/red].")
            if res.warnings.get("unsafe_eval"):
                warn_lines.append("Uses [red]'unsafe-eval'[/red].")
            if res.warnings.get("wildcard_sources"):
                warn_lines.append("Uses [dark_orange]wildcard sources (*)[/dark_orange].")
            if res.warnings.get("data_or_blob"):
                warn_lines.append("Allows [yellow]data:[/yellow] or [yellow]blob:[/yellow] sources.")
            if res.warnings.get("missing_report_to"):
                warn_lines.append("Missing [white]report-to[/white] directive.")
            if res.warnings.get("missing_https_and_upgrade"):
                warn_lines.append(
                    "No explicit [white]https://[/white] sources and missing [white]upgrade-insecure-requests[/white]."
                )

            if warn_lines:
                self.console.print(
                    Panel(
                        "\n".join(warn_lines),
                        title="Warnings",
                        border_style="yellow",
                        box=box.ROUNDED,
                    )
                )

            table = Table(
                title="Content-Security-Policy",
                show_header=True,
                header_style="bold",
                box=box.SIMPLE_HEAVY,
                expand=True,
                # show_lines=True,  # horizontal separators?
            )
            table.add_column("Directive", no_wrap=True)
            table.add_column("Source / Value", style="white")

            for p in res.policies:
                directive_label = f"[blue]{p.name}[/blue]"
                if p.is_deprecated:
                    directive_label += " [yellow](deprecated/legacy)[/yellow]"
                if p.help_text:
                    directive_label += f" [white]— {p.help_text}[/white]"

                if not p.items:
                    table.add_row(directive_label, "")
                    continue

                first = True
                for it in p.items:
                    expl = f" [dim]— {it.note}[/dim]" if it.note else ""
                    value = f"[{it.color}]{it.raw}[/{it.color}]{expl}"
                    table.add_row(directive_label if first else "", value)
                    first = False

            self.console.print(table)
            self.console.print()

    def render_many(self, results: List[URLResult]) -> str:
        lines: List[str] = []
        for res in results:
            lines.append("=" * 78)
            lines.append(f"{res.requested_url}  (fetched: {res.url})")
            lines.append("=" * 78)
            if res.error:
                lines.append(f"Error: {res.error}")
                lines.append("")
                continue

            if res.deprecated_used:
                lines.append("Deprecated/legacy directives present: " + ", ".join(res.deprecated_used))
                lines.append("")

            if res.csp_raw:
                lines.append("CSP (raw):")
                lines.append("  " + res.csp_raw)
                lines.append("")

            for p in res.policies:
                tag = f"[{p.name}]"
                if p.is_deprecated:
                    tag += " (deprecated/legacy)"
                if p.help_text:
                    tag += f" — {p.help_text}"
                lines.append(tag)

                if not p.items:
                    lines.append("  (no values)")
                    continue

                for it in p.items:
                    expl = f" — {it.note}" if it.note else ""
                    lines.append(f"  + {it.raw}{expl}")
                lines.append("")
            lines.append("")
        return "\n".join(lines)


class JsonRenderer(BaseRenderer):
    def render_many(self, results: List[URLResult]) -> str:
        def policy_to_dict(p: Policy) -> Dict:
            return {
                "name": p.name,
                "is_deprecated": p.is_deprecated,
                "help_text": p.help_text,
                "items": [
                    {"raw": i.raw, "normalized": i.normalized, "note": i.note, "color": i.color} for i in p.items
                ],
            }

        payload = [
            {
                "requested_url": r.requested_url,
                "fetched_url": r.url,
                "csp_raw": r.csp_raw,
                "deprecated_used": r.deprecated_used,
                "error": r.error,
                "policies": [policy_to_dict(p) for p in r.policies],
            }
            for r in results
        ]
        return json.dumps(payload, indent=2, sort_keys=False)


class LatexRenderer(BaseRenderer):
    def __init__(self, lang: str = "en"):
        self.lang = normalize_lang(lang)

    def _problems_list(self, res: URLResult) -> List[str]:
        names = {p.name for p in res.policies}
        problems: List[str] = []

        # missing-directive: treat missing default-src as a missing core directive
        if "default-src" not in names:
            problems.append("missing-directive")

        # unsafe: unsafe-inline or unsafe-eval
        if res.warnings.get("unsafe_inline") or res.warnings.get("unsafe_eval"):
            problems.append("unsafe")

        # all-origins: wildcard usage
        if res.warnings.get("wildcard_sources"):
            problems.append("all-origins")

        # data: data: or blob:
        if res.warnings.get("data_or_blob"):
            problems.append("data")

        # no-report: missing report-to
        if res.warnings.get("missing_report_to"):
            problems.append("no-report")

        # no-https: no explicit https sources AND missing upgrade-insecure-requests
        if res.warnings.get("missing_https_and_upgrade"):
            problems.append("no-https")

        order = ["missing-directive", "unsafe", "no-https", "all-origins", "data", "no-report"]
        return [p for p in order if p in problems]

    def _block_no_csp(self) -> str:
        if self.lang == "de":
            return r"""
\section{Content Security Policy}
\finding[status=Open]
{L}
{Content Security Policy}
{Die Webanwendung wird nicht durch eine Content Security Policy geschützt, die bspw. Cross-Site Scripting-Angriffe verhindern kann}
{Restriktive Content Security Policy konfigurieren}

Für die Webanwendung wird keine Content Security Policy (CSP) gesetzt, die einen zusätzlichen Schutz gegen Cross-Site Scripting (XSS)-Angriffe bieten würde.

Eine CSP ist ein zusätzliches Sicherheitsfeature, welches der Server über den \texttt{Content-Security-Policy}-HTTP-Header setzen kann, um dem Browser mitzuteilen, von welchen Quellen bestimmte Ressourcen geladen werden dürfen.
Abhängig vom Typ der Ressource, wie Skripte, Stylesheets, Grafiken etc. können verschiedene Einschränkungen konfiguriert werden, etwa von welchen Servern Dateien nachgeladen werden dürfen und ob Inline-Code erlaubt ist.
Wenn die CSP restriktiv konfiguriert ist, dient sie als zusätzlicher Schutz und hilft dabei, bestimmte Angriffe, insbesondere XSS, zu verhindern, da der Browser den injizierten Schadcode nicht laden und ausführen dürfte.

Derzeit wird jedoch keine CSP vom Server gesetzt.

Es sollte geprüft werden, ob eine restriktive CSP für die Webanwendung konfiguriert werden kann.
Dabei muss bedacht werden, dass dies Änderungen am Applikationscode erfordern kann, beispielsweise weil Inline-JavaScript-Code in dedizierte Dateien verschoben werden muss.
Bei Produkten eines anderen Herstellers sind solche Änderungen in der Regel nur von diesem sinnvoll durchführbar.

Es ist auch möglich, inkrementell auf eine effektive CSP hinzuarbeiten, indem bei mehreren Entwicklungsiterationen sukzessive striktere Regeln konfiguriert werden.
Eine CSP kann auch in einem \enquote{report-only}-Modus genutzt werden, bei dem Verstöße zunächst protokolliert, aber noch nicht blockiert werden.

Weitere Informationen können dem CSP-Artikel in den MDN Web Docs entnommen werden.\footnote{Content Security Policy: \url{https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP}}
Während der Entwicklung ist auch das Online-Werkzeug \enquote{CSP Evaluator}\footnote{CSP Evaluator: \url{https://csp-evaluator.withgoogle.com/}} hilfreich, mit dem sich die Probleme einer gegebenen CSP identifizieren lassen.
""".strip()
        else:
            return r"""
\section{Content Security Policy}
\finding[status=Open]
{L}
{Content Security Policy}
{The web application is not protected by a content security policy that can, for example, prevent cross-site scripting attacks}
{Configure restrictive content security policy}

No Content Security Policy (CSP) is set for the web application, which would provide additional protection against cross-site scripting (XSS) attacks.

A CSP is an additional security feature that the server can set via the \texttt{Content-Security-Policy} HTTP header to tell the browser from which sources certain resources may be loaded.
Depending on the type of resource, such as scripts, stylesheets, graphics, etc., various restrictions can be configured, such as from which servers files may be loaded and whether inline code is permitted.
If the CSP is configured restrictively, it serves as additional protection and helps to prevent certain attacks, especially XSS, as the browser is not allowed to load and execute the injected malicious code.

However, no CSP is currently set by the server.

It should be checked whether a restrictive CSP can be configured for the web application.
It must be borne in mind that this may require changes to the application code, for example because inline JavaScript code must be moved to dedicated files.
In the case of products from another manufacturer, such changes can usually only be made by that manufacturer.

It is also possible to work incrementally towards an effective CSP by configuring successively stricter rules for several development iterations.
A CSP can also be used in a \enquote{report-only} mode, in which violations are initially logged but not yet blocked.

Further information can be found in the CSP article in the MDN Web Docs.\footnote{Content Security Policy: \url{https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP}}
During development, the online tool \enquote{CSP Evaluator}\footnote{CSP Evaluator: \url{https://csp-evaluator.withgoogle.com/}}, which can be used to identify the problems of a given CSP, is also helpful.
""".strip()

    def render_many(self, results: List[URLResult]) -> str:
        provide_flash = r"\providecommand{\flash}{\syred{\faFlash}}"

        # If single result, keep previous behavior (detailed block per target)
        if len(results) == 1:
            res = results[0]
            if res.error or not res.csp_raw:
                return "\n".join([provide_flash, self._block_no_csp()])

            formatted = pretty_csp(res.csp_raw)
            formatted = highlight_csp_problems(formatted, res)
            problems = "{" + ",".join(self._problems_list(res)) + "}"
            block = rf"""
\begin{{sydeflisting}}{{csplisting}}
{formatted}
\end{{sydeflisting}}
\baustein[%
    findingattribute={{%
        %prefix={{}},
    }},
    einstufung=I,
    csplisting=csplisting,
    probleme={problems}, % Options: missing-directive,unsafe,no-https,all-origins,data,no-report
]
{{csp}}
""".strip()
            return "\n\n".join([provide_flash, block])

        # List input (multiple results)
        # has_any_csp = any((not r.error) and bool(r.csp_raw) for r in results)
        all_no_csp = all((r.error or not r.csp_raw) for r in results)

        # If all targets have no CSP
        if all_no_csp:
            return "\n".join([provide_flash, self._block_no_csp()])

        # At least one CSP exists:
        cumulative: List[str] = []
        for r in results:
            if r.error or not r.csp_raw:
                continue
            for p in self._problems_list(r):
                if p not in cumulative:
                    cumulative.append(p)

        problems_braced = "{" + ",".join(cumulative) + "}"

        template_block = rf"""
\begin{{sydeflisting}}{{csplisting}}
% intentionally left empty
\end{{sydeflisting}}
\baustein[%
    findingattribute={{%
        %prefix={{}},
    }},
    einstufung=I,
    % csplisting=csplisting,
    probleme={problems_braced}, % Options: missing-directive,unsafe,no-https,all-origins,data,no-report
]
{{csp}}
""".strip()

        headers = cumulative[:]  # copy
        headers.append("no csp set")
        num_problem_cols = len(headers)
        col_spec = "l" + ("c" * num_problem_cols)

        lines: List[str] = []
        lines.append(r"\begin{tabular}{" + col_spec + "}")

        header_titles = ["URL"] + headers
        lines.append(" \\ & ".join(header_titles) + r" \\ \hline")

        for r in results:
            url_label = r.requested_url
            row_cells: List[str] = [url_label]

            if r.error or not r.csp_raw:
                for _ in cumulative:
                    row_cells.append("")
                row_cells.append(r"\flash")
            else:
                plist = set(self._problems_list(r))
                for p in cumulative:
                    row_cells.append(r"\flash" if p in plist else "")
                row_cells.append("")

            lines.append(" \\ & ".join(row_cells) + r" \\")
        lines.append(r"\end{tabular}")

        table_block = "\n".join(lines)

        return "\n\n".join([provide_flash, template_block, table_block])


# ---------------------------------------
# CLI
# ---------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Inspect the Content-Security-Policy header for one or many URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              csp_check.py -u https://example.com
              csp_check.py -f urls.txt
              csp_check.py -u example.com -o results.txt
              csp_check.py -u example.com -o results.json --format json
              csp_check.py -u example.com -o results.tex --format latex --lang de
            """
        ),
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-u", "--url", help="Single URL/domain to check.")
    src.add_argument("-f", "--file", help="Path to a file with one URL per line.")

    p.add_argument("-c", "--cookies", help="Semicolon-separated cookies: 'a=b; c=d'", default=None)
    p.add_argument(
        "-o",
        "--output",
        help="Write results to this file. If omitted, prints to console (unless --format=latex).",
        default=None,
    )
    p.add_argument(
        "--format",
        choices=["text", "raw", "json", "latex"],
        default="text",
        help="Output format when writing to a file. Default: text.",
    )
    p.add_argument(
        "-l",
        "--lang",
        help="Language for LaTeX output (de|en|german|english). Default: de.",
        default="de",
    )

    return p


def read_urls_from_file(path: str) -> List[str]:
    urls: List[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            urls.append(s)
    return urls


def main() -> int:
    args = build_arg_parser().parse_args()
    cookies = parse_cookies(args.cookies)

    if args.url:
        urls = [args.url]
    else:
        try:
            urls = read_urls_from_file(args.file)
        except Exception as e:
            console.print(f"[red]Failed to read file:[/red] {e}")
            return 2

    results: List[URLResult] = [parse_csp(u, cookies) for u in urls]

    # File output
    if args.output:
        if args.format == "json":
            renderer: BaseRenderer = JsonRenderer()
        elif args.format == "latex":
            renderer = LatexRenderer(lang=args.lang)
        else:
            renderer = TextRenderer(console=None)

        try:
            content = renderer.render_many(results)
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(content)
            console.print(f"[green]Wrote output to[/green] {args.output}")
        except Exception as e:
            console.print(f"[red]Failed to write output:[/red] {e}")
            return 3
    else:
        # No file output -> print in terminal
        if args.format == "latex":
            content = LatexRenderer(lang=args.lang).render_many(results)
            print(content)
        elif args.format == "raw":
            for res in results:
                content = pretty_csp(res.csp_raw) if res else ""
                print(content)
        elif args.format == "json":
            renderer: BaseRenderer = JsonRenderer()
            content = renderer.render_many(results)
            print(content)
        else:
            TextRenderer(console=console).print_to_console(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())

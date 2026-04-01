"""
TAJ-CTF-Engine v2.0 — Aggressive Web Exploitation Automation
Created by Taj | CSYClub IIITK
"""
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os, sys, json

sys.path.insert(0, os.path.dirname(__file__))

from backend.modules.sqli          import SQLiModule
from backend.modules.xss           import XSSModule
from backend.modules.ssti          import SSTIModule
from backend.modules.lfi           import LFIModule
from backend.modules.cmdi          import CMDiModule
from backend.modules.jwt           import JWTModule
from backend.modules.ssrf          import SSRFModule
from backend.modules.idor          import IDORModule
from backend.modules.xxe           import XXEModule
from backend.modules.nosql         import NoSQLModule
from backend.modules.open_redirect import OpenRedirectModule
from backend.modules.dirbrute      import DirBruteModule
from backend.modules.headers       import HeadersModule
from backend.modules.typejuggle    import TypeJuggleModule
from backend.core.flag_hunter      import FlagHunter
from backend.core.crawler          import Crawler
from backend.core.requester        import Requester

app = Flask(__name__, static_folder="frontend")
CORS(app)

MODULE_MAP = {
    "sqli":          SQLiModule,
    "xss":           XSSModule,
    "ssti":          SSTIModule,
    "lfi":           LFIModule,
    "cmdi":          CMDiModule,
    "jwt":           JWTModule,
    "ssrf":          SSRFModule,
    "idor":          IDORModule,
    "xxe":           XXEModule,
    "nosql":         NoSQLModule,
    "open_redirect": OpenRedirectModule,
    "dirbrute":      DirBruteModule,
    "headers":       HeadersModule,
    "typejuggle":    TypeJuggleModule,
}

@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")

@app.route("/css/<path:filename>")
def css(filename):
    return send_from_directory("frontend/css", filename)

@app.route("/js/<path:filename>")
def js(filename):
    return send_from_directory("frontend/js", filename)


@app.route("/api/scan", methods=["POST"])
def scan():
    data       = request.get_json(force=True)
    target_url = data.get("url", "").strip()
    modules    = data.get("modules", list(MODULE_MAP.keys()))
    options    = data.get("options", {})
    do_crawl   = data.get("crawl", True)

    if not target_url:
        return jsonify({"error": "No target URL provided"}), 400

    results = {}
    flags   = []
    crawl_summary = {}

    if do_crawl:
        try:
            req = Requester(target_url, options)
            crawler = Crawler(target_url, req, max_pages=40)
            crawl_data = crawler.crawl()
            crawl_summary = {
                "endpoints_found": len(crawl_data.get("endpoints", [])),
                "forms_found":     len(crawl_data.get("forms", [])),
                "js_secrets":      crawl_data.get("js_secrets", [])[:10],
                "logs":            crawl_data.get("logs", [])[:30],
            }
            for f in crawl_data.get("flags", []):
                if f not in flags:
                    flags.append(f)
        except Exception as e:
            crawl_summary = {"error": str(e)}

    for mod_name in modules:
        cls = MODULE_MAP.get(mod_name)
        if not cls:
            continue
        try:
            mod    = cls(target_url, options)
            result = mod.run()
            results[mod_name] = result
            for f in FlagHunter.hunt(str(result)):
                if f not in flags:
                    flags.append(f)
            for f in result.get("flags", []):
                if f not in flags:
                    flags.append(f)
        except Exception as e:
            results[mod_name] = {"error": str(e), "status": "failed"}

    return jsonify({"url": target_url, "results": results,
                    "flags": flags, "crawl_summary": crawl_summary})


@app.route("/api/scan_module", methods=["POST"])
def scan_module():
    data       = request.get_json(force=True)
    target_url = data.get("url", "").strip()
    mod_name   = data.get("module", "").strip()
    options    = data.get("options", {})

    if not target_url or not mod_name:
        return jsonify({"error": "url and module are required"}), 400

    cls = MODULE_MAP.get(mod_name)
    if not cls:
        return jsonify({"error": f"Unknown module: {mod_name}"}), 404

    try:
        mod    = cls(target_url, options)
        result = mod.run()
        flags  = list(set(FlagHunter.hunt(str(result)) + result.get("flags", [])))
        return jsonify({"module": mod_name, "result": result, "flags": flags})
    except Exception as e:
        return jsonify({"module": mod_name, "error": str(e), "status": "failed"}), 500


@app.route("/api/crawl", methods=["POST"])
def crawl_only():
    data       = request.get_json(force=True)
    target_url = data.get("url", "").strip()
    options    = data.get("options", {})
    if not target_url:
        return jsonify({"error": "No target URL"}), 400
    req     = Requester(target_url, options)
    crawler = Crawler(target_url, req, max_pages=50)
    result  = crawler.crawl()
    return jsonify(result)


@app.route("/api/quick_flag", methods=["POST"])
def quick_flag():
    data       = request.get_json(force=True)
    target_url = data.get("url", "").strip()
    options    = data.get("options", {})
    if not target_url:
        return jsonify({"error": "No URL"}), 400

    flags = []
    findings = []
    req = Requester(target_url, options)

    r = req.get()
    if r:
        for f in FlagHunter.hunt_response(r):
            if f not in flags:
                flags.append(f)
                findings.append({"source": "direct", "flag": f})

    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    for path in ["/flag", "/flag.txt", "/api/flag", "/secret",
                 "/admin", "/.env", "/robots.txt", "/flag.php"]:
        r2 = req.raw_get(base + path)
        if r2 and r2.status_code == 200:
            for f in FlagHunter.hunt_response(r2):
                if f not in flags:
                    flags.append(f)
                    findings.append({"source": base + path, "flag": f})

    return jsonify({"flags": flags, "findings": findings})


@app.route("/api/modules", methods=["GET"])
def list_modules():
    return jsonify({"modules": list(MODULE_MAP.keys())})


@app.route("/api/payloads/<module_name>", methods=["GET"])
def get_payloads(module_name):
    path = os.path.join(os.path.dirname(__file__),
                        "backend", "payloads", f"{module_name}.json")
    if not os.path.exists(path):
        return jsonify({"error": "Payload file not found"}), 404
    with open(path) as f:
        return jsonify(json.load(f))


if __name__ == "__main__":
    print(r"""
  ████████╗ █████╗      ██╗       ██████╗████████╗███████╗
     ██╔══╝██╔══██╗     ██║      ██╔════╝╚══██╔══╝██╔════╝
     ██║   ███████║     ██║      ██║        ██║   █████╗  
     ██║   ██╔══██║██   ██║      ██║        ██║   ██╔══╝  
     ██║   ██║  ██║╚█████╔╝      ╚██████╗   ██║   ██║     
     ╚═╝   ╚═╝  ╚═╝ ╚════╝        ╚═════╝   ╚═╝   ╚═╝     
     v2.0 — 14 MODULES · CRAWLER · AGGRESSIVE FLAG EXTRACTION
                by TAJ | CSYClub IIITK
    """)
    app.run(debug=True, host="0.0.0.0", port=5000)

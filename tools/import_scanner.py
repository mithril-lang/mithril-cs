"""One-time deterministic source import. CI never fetches or loads Kotoba."""
import hashlib,json,pathlib,re,subprocess
REV="8bc8a410ad6836c55dedd5cf6ec3edea9e1f0b57"
REPO="cloud-itonami/app-itonami-zap-proxy"
def collect(checkout):
 def git(*args):return subprocess.check_output(["git","-C",checkout,*args])
 rows=git("ls-tree","-rl",REV,"src","test","resources","plugin","scripts/check-cwe-matrix.py","LICENSE").decode().splitlines()
 files={};manifest=[];test_before=[];test_after=[]
 for row in rows:
  meta,path=row.split("\t");mode,kind,blob,size=meta.split()
  if path.endswith(("plugin_entry.cljc","kbb_scan.cljc")):continue
  if not (path.endswith((".cljc",".py",".js",".edn")) or path=="LICENSE"):continue
  raw=git("show",REV+":"+path)
  assert hashlib.sha1(b"blob "+str(len(raw)).encode()+bytes([0])+raw).hexdigest()==blob
  text=raw.decode();dest="scanner/"+path.replace("kotoba/zap_proxy/","mithril/web_scanner/")
  if path.endswith(".cljc"):
   before=re.findall(r"\(deftest\s+([^\s()]+)",text)
   test_before.extend(before)
   text=text.replace("kotoba.zap-proxy","mithril.web-scanner").replace("kotoba-lang/zap-proxy","mithril-lang/mithril-cs/scanner")
   text=text.replace("kotoba.lang.text","clojure.string").replace("kotoba.lang.edn","clojure.edn").replace("kotoba.test","clojure.test")
   text=text.replace("kotoba.lang.fs-host","mithril.web-scanner.test-fs").replace("kotoba.lang.fs","mithril.web-scanner.test-fs")
   text=text.replace("str/lower","str/lower-case")
   text=text.replace('(.realpathSync (js/require "fs") ".")','(.getCanonicalPath (java.io.File. "."))')
   if path.endswith("stack_test.cljc"):
    text=text.replace("(:require ","(:require [cheshire.core :as json] ",1)
    text=text.replace("(.parse js/JSON ","(json/parse-string ")
    text=text.replace("(.-collection_state json)",'(get json "collection_state")')
    text=text.replace("(.-transport_failures (.-coverage json))",'(get-in json ["coverage" "transport_failures"])')
   after=re.findall(r"\(deftest\s+([^\s()]+)",text);assert before==after
   test_after.extend(after)
  elif path=="plugin/tools.py":
   start=text.index('    kbb = shutil.which("kbb")');end=text.index("    try:\n",start)
   text=text[:start]+'''    bb = shutil.which("bb")
    clojure = shutil.which("clojure")
    if bb:
        argv = [bb, "-m", "mithril.web-scanner.plugin-entry"]
    elif clojure:
        argv = [clojure, "-M", "-m", "mithril.web-scanner.plugin-entry"]
    else:
        return {"error": "neither bb nor clojure on PATH"}
'''+text[end:]
   text=text.replace("kotoba.zap-proxy","mithril.web-scanner")
   text=text[text.index("from __future__"):];text='"""Standalone Mithril scanner host adapter; Babashka preferred, Clojure fallback."""\n'+text
  elif path=="plugin/zap_api.py":
   text=text.replace('shutil.which("kbb")','shutil.which("bb")').replace('"kbb scanner engine unavailable"','"Babashka scanner engine unavailable"')
   text=text.replace('"kotoba.zap-proxy.kbb-scan"','"mithril.web-scanner.plugin-entry"')
   text=text.replace('[engine, "-M", "-m", entry]','[engine, "-m", entry]')
  elif path=="plugin/test_tools.py":
   text=text.replace('test_prefers_kbb_when_both_available','test_prefers_bb_when_both_available')
   text=text.replace('test_falls_back_to_clojure_when_kbb_absent','test_falls_back_to_clojure_when_bb_absent')
   text=text.replace('("kbb", "clojure")','("bb", "clojure")')
   text=text.replace('calls["argv"][:4], ["/usr/bin/kbb", "-M", "-m", "kotoba.zap-proxy.kbb-scan"]',
                     'calls["argv"][:3], ["/usr/bin/bb", "-m", "mithril.web-scanner.plugin-entry"]')
   text=text.replace('"kotoba.zap-proxy.plugin-entry"','"mithril.web-scanner.plugin-entry"')
  elif path=="plugin/test_zap_api.py":
   text=text.replace('shutil.which("kbb")','shutil.which("bb")').replace('"kbb unavailable"','"Babashka unavailable"')
  elif path=="plugin/zap_fetch.js":
   text="\n".join(line for line in text.splitlines() if "drop apostrophes" not in line)+"\n"
   # Original JS helper remains only for original host transport tests. Preserve wire strings.
   text=text.replace('":" + k.toLowerCase() + " " + val(v)','esc(k.toLowerCase()) + " " + val(v)')
  if dest.startswith("scanner/resources/mithril/web_scanner/"):
   dest=dest.replace("scanner/resources/mithril/web_scanner/","scanner/resources/zap_proxy/")
  files[dest]=text
  manifest.append({"source_path":path,"git_blob":blob,"source_sha256":hashlib.sha256(raw).hexdigest(),
                   "owned_path":dest,"owned_sha256":hashlib.sha256(text.encode()).hexdigest()})
 assert test_before==test_after and len(test_after)>=311
 assert not any(re.search(r"\[(kotoba\.(lang|test)|kotoba-lang/)",s) for p,s in files.items() if p.endswith(".cljc"))
 files["scanner/PROVENANCE.json"]=json.dumps({"source_repository":REPO,"source_revision":REV,
   "ownership":"Mithril-owned derivative snapshot; original MIT attribution retained",
   "runtime_dependencies":["Babashka","Python standard library"],"external_fetch_at_runtime":False,
   "test_names_preserved":test_after,"files":manifest},indent=2)+"\n"
 return files

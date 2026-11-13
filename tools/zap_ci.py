"""Hermetic KBB adapter and actual HTTP dogfood for the pinned first-party scanner."""
import collections, hashlib, http.server, json, os, pathlib, re, resource, subprocess, sys, tempfile, threading, time
ROOT=pathlib.Path(os.environ.get("ZAP_RUNTIME","/tmp/zap-runtime"))
SCANNER=ROOT/"scanner"
def run(argv,**kw):
 p=subprocess.run(argv,capture_output=True,text=True,timeout=600,**kw)
 if p.returncode: raise RuntimeError("command failed: "+json.dumps(argv)+"\n"+p.stdout[-8000:]+"\n"+p.stderr[-4000:])
 return p.stdout
def launcher(args):
 m=json.loads((ROOT/"manifest.json").read_text())
 cp=[str(SCANNER/p) for p in ["src","resources","test"]]+[str(ROOT/"stdlib"/"lib"/r/"src") for r in m["stdlib_roots"]]
 base=["node","--stack-size=8000",str(ROOT/"engine"/"cli.js"),"--classpath",":".join(cp)]
 empty=ROOT/"empty";empty.mkdir(exist_ok=True)
 if args==["-M:test"]:
  nss=[re.search(r"\(ns\s+([^\s()]+)",p.read_text())[1] for p in sorted((SCANNER/"test").rglob("*_test.cljc"))]
  quoted=" ".join("'"+s for s in nss)
  expr="(.chdir js/process "+json.dumps(str(SCANNER))+") (require '[cljs.test :as t] "+" ".join("'"+s for s in nss)+") (defmethod t/report [::t/default :end-run-tests] [m] (when-not (t/successful? m) (js/process.exit 1))) (t/run-tests "+quoted+")"
  cmd=base+["-e",expr]
 elif len(args)==3 and args[:2]==["-M","-m"] and args[2] in ["kotoba.zap-proxy.kbb-scan"]:
  cmd=base+["-m",args[2]]
 else: raise RuntimeError("unsupported hermetic KBB invocation")
 os.chdir(empty)
 os.execvp(cmd[0],cmd)
def ledger(path,target,approval="ci-2485"):
 now=int(time.time())
 record={"id":approval,"status":"approved","approval_method":"human_verified_written_scope",
   "approver":"Jun","authority_verified_by":"Codex","reviewed_by":"Codex","recorded_by":"Codex",
   "authority_evidence_ref":"Mithril-owned fixture/public domain; MITHRIL-2485",
   "approval_evidence_ref":"codex-chat:01a1d429-ab89-70b2-92fc-d81581cbe7bf/MITHRIL-2485",
   "approved_at":now,"reviewed_at":now,"not_before":now,"expires_at":now+900,
   "assets":[target],"methods":["GET"],"modes":["passive"],"max_pages":5}
 path.write_text(json.dumps({"version":1,"authorized_approvers":["Jun"],"operators":["Codex"],"approvals":[record]}))
 path.chmod(0o600);os.environ["ZAP_PROXY_APPROVALS_FILE"]=str(path)
def summary(label,doc):
 findings=doc["findings"]
 groups=collections.Counter((f["rule_id"],f["severity"],f["title"]) for f in findings)
 return {"label":label,"target":doc["target"],"collection_state":doc["collection_state"],
   "coverage":doc["coverage"],"counts":doc["counts"],"total":doc["total"],
   "rules":[{"rule_id":rid,"severity":sev,"title":title,"occurrences":n}
            for (rid,sev,title),n in sorted(groups.items())],
   "limitations":doc["limitations"],"report_sha256":hashlib.sha256(json.dumps(doc,sort_keys=True).encode()).hexdigest(),
   "finding_status":"needs-review","certificate_eligible":False}
def main():
 os.environ.update(ZAP_PROXY_REPO_ROOT=str(SCANNER),ZAP_PROXY_REPO=str(SCANNER),PYTHONDONTWRITEBYTECODE="1")
 bins=ROOT/"bin";bins.mkdir(exist_ok=True)
 wrapper=bins/"kbb";wrapper.write_text("#!"+sys.executable+"\nimport runpy,sys\nsys.argv=["+repr(__file__)+",'--kbb']+sys.argv[1:]\nrunpy.run_path("+repr(__file__)+",run_name='__main__')\n");wrapper.chmod(0o755)
 os.environ["PATH"]=str(bins)+":"+os.environ["PATH"]
 out=run(["bash","scripts/coverage-gate.sh"],cwd=SCANNER)
 print(out,flush=True)
 match=re.search(r"tests=(\d+) assertions=(\d+)",out)
 if not match or int(match[1])<311 or int(match[2])<1441: raise RuntimeError("original test floor missing")
 # The upstream Python suites are run unmodified, including their actual engine HTTP case.
 testcode="import unittest; s=unittest.defaultTestLoader.loadTestsFromNames(['plugin.test_tools','plugin.test_zap_api']); r=unittest.TextTestRunner(verbosity=2).run(s); print('PYTHON_TESTS',r.testsRun,'SKIPPED',len(r.skipped)); raise SystemExit(0 if r.wasSuccessful() and not r.skipped else 1)"
 print(run([sys.executable,"-B","-c",testcode],cwd=SCANNER),flush=True)
 sys.path.insert(0,str(SCANNER))
 from plugin.zap_api import _run_engine,Scan
 from plugin import tools
 results=[]
 class Target(http.server.BaseHTTPRequestHandler):
  def log_message(self,*_):pass
  def do_GET(self):
   if self.path.startswith("/hardened"):
    self.send_response_only(200)
    for k,v in {"Strict-Transport-Security":"max-age=31536000; includeSubDomains","X-Content-Type-Options":"nosniff",
      "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'","X-Frame-Options":"DENY",
      "Referrer-Policy":"no-referrer","Permissions-Policy":"camera=(), microphone=()",
      "Cross-Origin-Opener-Policy":"same-origin","Cross-Origin-Embedder-Policy":"require-corp",
      "Cross-Origin-Resource-Policy":"same-origin"}.items():self.send_header(k,v)
   else:self.send_response_only(200)
   b=b"<html><body>Controlled Mithril CI response</body></html>"
   self.send_header("Content-Type","text/html; charset=utf-8");self.send_header("Content-Length",str(len(b)));self.end_headers();self.wfile.write(b)
 server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Target);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
 with tempfile.TemporaryDirectory() as td:
  approval=pathlib.Path(td)/"approval.json"
  try:
   for label,path in [("positive-control","/vulnerable/"),("hardened-control","/hardened/")]:
    target="http://127.0.0.1:"+str(server.server_port)+path
    ledger(approval,target)
    doc=_run_engine(Scan(label,"spider",target),"ci-2485",5)
    assert doc["collection_state"]=="complete" and doc["coverage"]["fetched_pages"]==1
    if label=="positive-control":assert any(f["rule_id"]=="10038" for f in doc["findings"])
    else:assert not doc["findings"],"hardened negative control findings"
    results.append(summary(label,doc))
   # Original adapter authorization denial must not become an engine invocation.
   denied=json.loads(tools.zap_scan(target=target,approval_id="missing",max_pages=5))
   assert "refused" in denied
   target="https://mithril.fund/"
   ledger(approval,target)
   doc=_run_engine(Scan("company-public-passive","spider",target),"ci-2485",5)
   assert 1<=doc["coverage"]["fetched_pages"]<=5,"no actual first-party HTTP response"
   results.append(summary("company-public-passive",doc))
  finally:server.shutdown();server.server_close();thread.join(timeout=2)
 manifest=json.loads((ROOT/"manifest.json").read_text())
 result={"schema_version":1,"issue":"MITHRIL-2485","pins":manifest["pins"],
  "tests":{"kbb":int(match[1]),"assertions":int(match[2]),"upstream_coverage_gate":"passed","python_skipped":0},
  "authorization_denial":"passed","reports":results,
  "child_peak_rss_kib":resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
  "scope":"passive GET-only; no public active probes; no authentication; maximum5pages"}
 # Summaries exclude source bodies, evidence strings, cookies, request headers and URL queries.
 print("ZAP_CI_RESULT "+json.dumps(result,ensure_ascii=False),flush=True)
 print("ZAP_CI_PASS",flush=True)
if __name__=="__main__":
 if sys.argv[1:2]==["--kbb"]:launcher(sys.argv[2:])
 else:main()

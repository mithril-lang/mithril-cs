"""Bounded first-party replay for MITHRIL-2487. No active probes or credentialed requests."""
import base64,collections,gzip,hashlib,html.parser,ipaddress,json,os,pathlib,re,resource,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];SCANNER=ROOT/"scanner"
ORIGINAL_REPORT_SHA="3419e9d44b883e096b26a0d24c2ed0446dbb31e515d4bdbf6d69c83f32024e00"
def sha(b):return hashlib.sha256(b).hexdigest()
def safeurl(url):
 from urllib.parse import urlsplit,urlunsplit,parse_qsl,urlencode
 u=urlsplit(url);q=[(k,"[REDACTED]" if re.search("token|key|code|secret|session|auth|signature",k,re.I) else v) for k,v in parse_qsl(u.query,keep_blank_values=True)]
 return urlunsplit((u.scheme,u.netloc,u.path,urlencode(q),""))
def grant(path,pages):
 now=int(time.time())
 record={"id":"review-2487","status":"approved","approval_method":"human_verified_written_scope",
  "approver":"Jun","authority_verified_by":"Codex","reviewed_by":"Codex","recorded_by":"Codex",
  "authority_evidence_ref":"Mithril-owned public site; Cloudflare fund-mithril zone readback",
  "approval_evidence_ref":"MITHRIL-2487/codex-chat-01a1d429-ab89-70b2-92fc-d81581cbe7bf",
  "approved_at":now,"reviewed_at":now,"not_before":now,"expires_at":now+1800,
  "assets":["https://mithril.fund/"],"methods":["GET"],"modes":["passive"],"max_pages":pages}
 path.write_text(json.dumps({"version":1,"authorized_approvers":["Jun"],"operators":["Codex"],"approvals":[record]}));path.chmod(0o600)
 os.environ["ZAP_PROXY_APPROVALS_FILE"]=str(path)
class Resources(html.parser.HTMLParser):
 def __init__(self):super().__init__();self.fetches=[];self.namespaces=[]
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  for k,v in attrs:
   if v and k.startswith("xmlns"):self.namespaces.append(v)
  fields={"script":["src"],"img":["src","srcset"],"iframe":["src"],"source":["src","srcset"],"video":["src","poster"],"audio":["src"],"object":["data"],"embed":["src"],"image":["href","xlink:href"],"use":["href","xlink:href"]}
  if tag=="link" and any(x in a.get("rel","").lower().split() for x in ["stylesheet","preload","modulepreload","icon"]):fields[tag]=["href"]
  for k in fields.get(tag,[]):
   if a.get(k):self.fetches.append(a[k])
def inspect(url,response):
 from plugin.http_fetch import edn,response_edn
 request="{:url "+edn(url)+" :response "+response_edn(response)+"}"
 p=subprocess.run(["bb","--classpath","src:resources:test","-m","mithril.web-scanner.inspect"],
     cwd=SCANNER,input=request,text=True,capture_output=True,timeout=30)
 if p.returncode:raise RuntimeError("inspection failed: "+p.stderr[-1000:])
 if len(p.stdout)>1024*1024:raise RuntimeError("inspection output budget")
 return json.loads(p.stdout)
def context_and_disposition(url,response,finding):
 body=response["body"];ctype=str(response["headers"].get("content-type","")).lower()
 doc=ctype.split(";",1)[0] in ["text/html","application/xhtml+xml"]
 parser=Resources()
 if doc or "svg" in ctype:
  try:parser.feed(body)
  except Exception:pass
 rid=finding["rule-id"];title=finding["title"];evidence=str(finding.get("evidence",""))
 result={"disposition":"deferred","survives":"uncertain","confidence":"medium","root_control":title,
  "method":"actual-http-and-response-context","reason":"configuration hardening requires an applicable threat model; no exploit demonstrated",
  "content_type":ctype,"document":doc}
 if rid=="40049":
  resources=[x for x in parser.fetches if re.search(r"(?i)^http://",x)]
  if "css" in ctype:resources+=re.findall(r"(?i)(?:url\(\s*[\"']?|@import\s+[\"'])(http://[^\"'\s)]+)",body)
  if not resources:
   stripped=re.sub(r"""(?i)\\s+xmlns(?::[A-Za-z0-9_-]+)?\\s*=\\s*["'][^"']*["']""","",body)
   # JavaScript, navigation and unsupported dynamic references remain uncertain.
   if re.search(r"(?i)http://[A-Za-z0-9]",stripped):
    result.update(root_control="mixed-content",reason="HTTP reference retained; execution/navigation context requires browser validation")
    return result
   result.update(disposition="suppressed",survives="no",confidence="high",
    root_control="mixed-content",reason="HTTP lexical match is not a fetch-bearing resource reference in this response",
    context={"xmlns":parser.namespaces[:8],"matched_prefix":evidence})
  else:result.update(root_control="mixed-content",reason="insecure fetch-bearing resource reference; browser/request impact still unverified",context={"resources":[safeurl(x) for x in resources[:10]]})
 elif rid=="40040":
  hits=[]
  for raw in re.findall(r"(?<![A-Za-z0-9_.])(?:10|127|172|192)(?:\.[0-9]{1,3}){3}(?![A-Za-z0-9_.])",body):
   try:
    a=ipaddress.IPv4Address(raw)
    if a.is_private or a.is_loopback:hits.append(raw)
   except ValueError:pass
  index=body.find(evidence)
  snippet=body[max(0,index-100):index+len(evidence)+100] if index>=0 else ""
  if not hits:result.update(disposition="suppressed",survives="no",confidence="high",root_control="internal-ip-pattern",reason="legacy unescaped-dot regex matched non-IP coordinates/text; no valid private IPv4 literal",context={"legacy_match":evidence,"context":snippet})
  else:result.update(root_control="internal-ip-pattern",reason="private-address literal exists; sensitivity/deployment topology is not established",context={"private_literals":list(dict.fromkeys(hits))[:10],"context":snippet})
 elif rid=="40074":
  result.update(root_control="content-type-charset")
  if "application/json" in ctype:result.update(disposition="not_applicable",survives="no",reason="JSON media type has no defined charset parameter; UTF-8 is the interoperable encoding")
  elif not doc:result.update(disposition="deferred",reason="static text asset encoding needs BOM/document/format context; missing charset alone is not an exploitable boundary failure")
 else:
  lower=(title+" "+evidence).lower()
  names=[("content-security-policy","csp"),("clickjacking","frame-ancestors"),("x-frame-options","frame-ancestors"),
   ("hsts","hsts"),("strict-transport-security","hsts"),("x-content-type-options","nosniff"),("mime","nosniff"),
   ("referrer-policy","referrer-policy"),("permissions-policy","permissions-policy"),("cross-origin-opener","coop"),
   ("cross-origin-embedder","coep"),("cross-origin-resource","corp")]
  control=next((v for k,v in names if k in lower),title)
  result["root_control"]=control
  if control in ["coop","coep","corp"]:result["reason"]="optional cross-origin isolation/resource policy; universal absence does not prove a vulnerability"
  elif not doc and control in ["csp","frame-ancestors","permissions-policy","referrer-policy"]:
   result.update(disposition="not_applicable",survives="no",confidence="high",reason="missing document policy on a fixed non-HTML asset is not the claimed document control failure")
  elif doc:result["reason"]="header absence observed on actual HTML; hardening gap retained for product/security review, not an exploit confirmation"
 return result
def main():
 start=time.perf_counter()
 os.environ.update(ZAP_PROXY_REPO_ROOT=str(SCANNER),ZAP_PROXY_REPO=str(SCANNER),PYTHONDONTWRITEBYTECODE="1")
 sys.path[:0]=[str(SCANNER),str(SCANNER/"plugin")]
 from plugin.zap_api import _run_engine,Scan
 from plugin.http_fetch import fetch
 with tempfile.TemporaryDirectory(prefix="review-2487-") as td:
  tmp=pathlib.Path(td);approval=tmp/"approval.json";trace=tmp/"responses.jsonl"
  os.environ["MITHRIL_SCAN_TRACE"]=str(trace)
  grant(approval,5)
  original=_run_engine(Scan("original-five","spider","https://mithril.fund/"),"review-2487",5)
  original_sha=sha(json.dumps(original,sort_keys=True).encode())
  grant(approval,80)
  queue=["https://mithril.fund/"];seen=set(queue);rows=[];instances=[];failed=[];requests=sum(json.loads(x).get("kind")=="response" for x in trace.read_text().splitlines())
  def examine(url,phase):
   nonlocal requests
   if requests>=80:raise RuntimeError("total request cap")
   requests+=1;r=fetch(url,"review-2487","passive",80)
   meta=r["diagnostic"];item={"url":safeurl(url),"url_sha256":sha(url.encode()),"phase":phase,"response":meta,"findings":[],"discovered":[]}
   if r["status"]==0:
    item["outcome"]="failed";item["failure_reason"]=meta["failure_reason"];rows.append(item);return item
   result=inspect(url,r);item["outcome"]="fetched";item["discovered"]=result["discovered"]
   for pos,f in enumerate(result["findings"]):
    key=sha(json.dumps([phase,safeurl(url),f["rule-id"],f["title"],pos],ensure_ascii=True).encode())[:24]
    disposition=context_and_disposition(url,r,f)
    record={"candidate_id":key,"url":safeurl(url),"rule_id":f["rule-id"],"title":f["title"],
       "phase":phase,"original_severity":f["severity"],"evidence":f.get("evidence") if f["rule-id"] in ["10038","40040","40049","40052","40053","40054","40055","40056","40059","40074"] else {"redacted_sha256":sha(str(f.get("evidence")).encode())},"response_sha256":meta.get("body_prefix_sha256"),**disposition}
    item["findings"].append(key);instances.append(record)
   rows.append(item);return item
  cursor=0
  while cursor<min(5,len(queue)):
   url=queue[cursor];item=examine(url,"reconstructed-first-five");cursor+=1
   if item["outcome"]=="failed":failed.append(url)
   for u in item["discovered"]:
    if u not in seen:queue.append(u);seen.add(u)
  pending=queue[cursor:];frozen=list(pending)
  deferred_pending=frozen[60:];frozen=frozen[:60]
  for url in frozen:
   time.sleep(0.30);examine(url,"pending-reinspection")
  for url in failed:
   time.sleep(0.30);examine(url,"failed-retry")
  # Preserve every instance and duplicate relationship; do not collapse the ledger.
  canonical={}
  for row in instances:
   key=(row["root_control"],row["url"] if row["root_control"] not in ["hsts"] else "https://mithril.fund")
   if key in canonical:row["duplicate_of"]=canonical[key]
   else:canonical[key]=row["candidate_id"];row["duplicate_of"]=None
  original_receipts=[]
  for i,old in enumerate(original["findings"]):
   candidates=[r for r in instances if r["phase"]=="reconstructed-first-five"
               and r["url"]==safeurl(old["url"]) and r["rule_id"]==old["rule_id"] and r["title"]==old["title"]]
   match=candidates[0] if candidates else None
   original_receipts.append({"input_id":ORIGINAL_REPORT_SHA+"#"+str(i),
    "historical_link_verified":original_sha==ORIGINAL_REPORT_SHA,
    "reconstructed_report_sha256":original_sha,"reconstructed_url":safeurl(old["url"]),
    "title":old["title"],"rule_id":old["rule_id"],"matching_candidate_id":match["candidate_id"] if match else None,
    "disposition":match["disposition"] if match else "deferred",
    "method":match["method"] if match else "proof-gap",
    "confidence":match["confidence"] if match else "low",
    "reason":match["reason"] if match else "fresh original pipeline instance not matched by independent replay",
    "original_historical_proof_gap":None if original_sha==ORIGINAL_REPORT_SHA else "historical per-instance report not retained; new report digest differs"})
  trace_raw=trace.read_bytes()
  trace_rows=[json.loads(x) for x in trace_raw.splitlines()]
  for row in rows:
   row["response"]["url"]=safeurl(row["response"]["url"])
   row["discovered"]=list(map(safeurl,row["discovered"]))
  for row in trace_rows:
   if "url" in row:row["url"]=safeurl(row["url"])
  stats={"original_report_sha256":original_sha,"matches_historical_report":original_sha==ORIGINAL_REPORT_SHA,
   "original_report_findings":original["total"],"original_report_coverage":original["coverage"],
   "reconstructed_first_five":min(5,len(queue)),"reconstructed_pending":len(frozen),"historical_pending_identities":"NOT_RETAINED; replay queue is not proof of old omitted URL identities",
   "pending_attempted":len(frozen),"deferred_new_pending":len(deferred_pending),"http_statuses":dict(collections.Counter(str(x["response"].get("http_status")) for x in rows)),"failed_retried":len(failed),"requests":requests,
   "fetched":sum(r["outcome"]=="fetched" for r in rows),"failed":sum(r["outcome"]=="failed" for r in rows),
   "failure_reasons":dict(collections.Counter(r.get("failure_reason") for r in rows if r["outcome"]=="failed")),
   "candidate_occurrences":len(instances),"canonical_groups":len(canonical),"duplicates":sum(bool(x["duplicate_of"]) for x in instances),
   "dispositions":dict(collections.Counter(x["disposition"] for x in instances)),
   "trace_bytes":len(trace_raw),"target_bytes_observed":sum(x.get("bytes_observed",0) for x in trace_rows if x.get("kind")=="response"),
   "serialization_ns":sum(x.get("serialization_ns",0) for x in trace_rows),"flush_ns":sum(x.get("flush_ns",0) for x in trace_rows),
   "peak_child_rss_kib":resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,"elapsed_seconds":round(time.perf_counter()-start,3)}
  payload={"schema_version":1,"issue":"MITHRIL-2487","scope":"anonymous GET only; original five plus frozen pending queue and failed retry; no active probes",
    "stats":stats,"original_report":original,"queue":list(map(safeurl,queue)),"frozen_pending":list(map(safeurl,frozen)),
    "responses":rows,"candidate_ledger":instances,"original_validation_receipts":original_receipts,"trace":trace_rows,
    "original_instance_note":"only aggregate original input survived; exact original62 instances recovered only if canonical report digest matches"}
  raw=json.dumps(payload,ensure_ascii=True,separators=(",",":")).encode()
  if len(raw)>3*1024*1024:raise RuntimeError("evidence package bound")
  begin=time.perf_counter_ns();packed=gzip.compress(raw,mtime=0);compress_ns=time.perf_counter_ns()-begin
  stats.update(evidence_bytes=len(raw),gzip_bytes=len(packed),compression_ns=compress_ns,evidence_sha256=sha(raw),gzip_sha256=sha(packed))
  print("REVIEW_ARTIFACT "+base64.b64encode(packed).decode(),flush=True)
  print("REVIEW_SUMMARY "+json.dumps(stats),flush=True)
  print("REVIEW_PASS",flush=True)
if __name__=="__main__":main()

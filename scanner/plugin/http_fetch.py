"""Fixed GET helper: per-request scope, exact strings and optional bounded review metadata."""
import hashlib,json,os,stat,sys,time,urllib.request,urllib.error
from authorization import authorize_request,load_ledger
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*_):return None
SAFE_HEADERS={"content-type","content-length","content-security-policy","content-security-policy-report-only",
 "strict-transport-security","x-content-type-options","x-frame-options","referrer-policy","permissions-policy",
 "cross-origin-opener-policy","cross-origin-embedder-policy","cross-origin-resource-policy","cache-control"}
def trace(event):
 path=os.environ.get("MITHRIL_SCAN_TRACE")
 if not path:return
 if not os.path.isabs(path):raise RuntimeError("review trace must be absolute")
 start=time.perf_counter_ns();raw=json.dumps({"kind":"response",**event},ensure_ascii=True,separators=(",",":")).encode()
 serialization=time.perf_counter_ns()-start
 if len(raw)>16384:raise RuntimeError("review metadata budget")
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_size>2*1024*1024:raise RuntimeError("review metadata custody")
  start=time.perf_counter_ns()
  with os.fdopen(fd,"ab",closefd=False) as stream:
   stream.write(raw+b"\n");stream.flush()
   io_ns=time.perf_counter_ns()-start
   stream.write(json.dumps({"kind":"trace-metrics","url_sha256":hashlib.sha256(event["url"].encode()).hexdigest(),
                            "bytes":len(raw)+1,"serialization_ns":serialization,"flush_ns":io_ns},separators=(",",":")).encode()+b"\n")
   stream.flush()
 finally:os.close(fd)
def fetch(url,approval,mode,pages):
 if authorize_request(load_ledger(),approval,url,mode,max_pages=pages) is None:raise PermissionError("no current grant")
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 start=time.perf_counter_ns();meta={"url":url,"method":"GET","headers":{},"http_status":None,"bytes_observed":0,"body_complete":False}
 try:
  try:response=opener.open(urllib.request.Request(url,method="GET",headers={"User-Agent":"Mithril-CS/0.1 (+https://cs.mithril.fund; passive-security-check)","Accept":"text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5"}),timeout=15)
  except urllib.error.HTTPError as e:response=e
  with response:
   headers={}
   for k in response.headers.keys():
    values=response.headers.get_all(k)
    headers[k.lower()]=values if k.lower()=="set-cookie" else ", ".join(values)
   meta.update(http_status=response.status,headers={k:v for k,v in headers.items() if k in SAFE_HEADERS})
   b=response.read(1048577)
   meta.update(bytes_observed=len(b),body_prefix_sha256=hashlib.sha256(b).hexdigest(),body_complete=len(b)<=1048576,
               elapsed_ns=time.perf_counter_ns()-start)
   if len(b)>1048576:
    meta["failure_reason"]="response-byte-limit";trace(meta)
    return {"status":0,"headers":{},"body":"response exceeded byte limit","diagnostic":meta}
   meta["failure_reason"]=None;trace(meta)
   return {"status":response.status,"headers":headers,"body":b.decode("utf-8","replace"),"diagnostic":meta}
 except (OSError,urllib.error.URLError) as e:
  meta.update(elapsed_ns=time.perf_counter_ns()-start,failure_reason="transport-error",error_class=type(e).__name__)
  trace(meta)
  return {"status":0,"headers":{},"body":"transport failed","diagnostic":meta}
def edn(x):
 if isinstance(x,dict):return "{"+ " ".join(edn(k)+" "+edn(v) for k,v in x.items())+"}"
 if isinstance(x,list):return "["+" ".join(map(edn,x))+"]"
 if isinstance(x,int):return str(x)
 return json.dumps(x,ensure_ascii=True)
def response_edn(response):
 return "{:status "+str(response["status"])+" :headers "+edn(response["headers"])+" :body "+edn(response["body"])+"}"
if __name__=="__main__":
 try:print(response_edn(fetch(sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]))))
 except PermissionError:sys.exit(3)

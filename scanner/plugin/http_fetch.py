"""Fixed GET helper: current authorization, no redirect, bounded response, exact strings."""
import json,sys,urllib.request,urllib.error
from authorization import authorize_request,load_ledger
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*_):return None
def fetch(url,approval,mode,pages):
 if authorize_request(load_ledger(),approval,url,mode,max_pages=pages) is None:raise PermissionError("no current grant")
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 try:
  try:response=opener.open(urllib.request.Request(url,method="GET"),timeout=15)
  except urllib.error.HTTPError as e:response=e
  with response:
   b=response.read(1048577)
   if len(b)>1048576:return {"status":0,"headers":{},"body":"response exceeded byte limit"}
   headers={}
   for k in response.headers.keys():
    values=response.headers.get_all(k)
    headers[k.lower()]=values if k.lower()=="set-cookie" else ", ".join(values)
   return {"status":response.status,"headers":headers,"body":b.decode("utf-8","replace")}
 except (OSError,urllib.error.URLError):return {"status":0,"headers":{},"body":"transport failed"}
def edn(x):
 if isinstance(x,dict):return "{"+ " ".join(edn(k)+" "+edn(v) for k,v in x.items())+"}"
 if isinstance(x,list):return "["+" ".join(map(edn,x))+"]"
 if isinstance(x,int):return str(x)
 return json.dumps(x,ensure_ascii=True)
if __name__=="__main__":
 try:print(edn(fetch(sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]))))
 except PermissionError:sys.exit(3)

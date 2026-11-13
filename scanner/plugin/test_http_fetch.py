"""Actual HTTP fidelity and redirect/scope regression cases for standalone transport."""
import http.server,json,os,pathlib,sys,tempfile,threading,unittest
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from http_fetch import fetch,response_edn
from plugin.test_zap_api import ledger
class HTTPContracts(unittest.TestCase):
 def setUp(self):
  self.hits=[]
  hits=self.hits
  class Target(http.server.BaseHTTPRequestHandler):
   def log_message(self,*_):pass
   def do_GET(self):
    self.server.last_user_agent=self.headers.get("User-Agent")
    hits.append(self.path)
    if self.path=="/app/redirect":
     self.send_response_only(302);self.send_header("Location","/outside");body=b"redirect"
    else:
     self.send_response_only(200);self.send_header("Content-Security-Policy","default-src 'none'")
     body="Mithril's response 日本語".encode()
    self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
  self.server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Target)
  self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
  self.tmp=tempfile.TemporaryDirectory();p=pathlib.Path(self.tmp.name)/"approval";p.write_text(json.dumps(ledger(self.server.server_port)));p.chmod(0o600)
  self.old=os.environ.get("ZAP_PROXY_APPROVALS_FILE");os.environ["ZAP_PROXY_APPROVALS_FILE"]=str(p)
  self.url="http://127.0.0.1:"+str(self.server.server_port)
 def tearDown(self):
  self.server.shutdown();self.server.server_close();self.thread.join(timeout=2);self.tmp.cleanup()
  if self.old is None:os.environ.pop("ZAP_PROXY_APPROVALS_FILE",None)
  else:os.environ["ZAP_PROXY_APPROVALS_FILE"]=self.old
 def test_exact_header_and_body(self):
  r=fetch(self.url+"/app/","reviewed-1","passive",5)
  self.assertEqual(r["headers"]["content-security-policy"],"default-src 'none'")
  self.assertEqual(r["body"],"Mithril's response 日本語")
  self.assertEqual(self.server.last_user_agent,"Mithril-CS/0.1 (+https://cs.mithril.fund; passive-security-check)")
 def test_edn_envelope_and_string_headers(self):
  out=response_edn({"status":200,"headers":{"content-security-policy":"default-src 'none'"},"body":"Mithril's"})
  self.assertTrue(out.startswith('{:status 200 :headers {"content-security-policy"'))
  self.assertIn("default-src 'none'",out);self.assertIn("Mithril's",out)
 def test_no_redirect_follow(self):
  r=fetch(self.url+"/app/redirect","reviewed-1","passive",5)
  self.assertEqual(r["status"],302);self.assertEqual(self.hits,["/app/redirect"])
 def test_scope_denial_before_socket(self):
  with self.assertRaises(PermissionError):fetch(self.url+"/outside","reviewed-1","passive",5)
  self.assertEqual(self.hits,[])

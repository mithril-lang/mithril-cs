"""Source-transport and report safety contracts; no public network."""
import gzip,io,json,tarfile,tempfile,unittest,pathlib
import zap_snapshot,zap_ci
def archive(files):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode="w") as t:
  for name,b in files.items():
   i=tarfile.TarInfo(name);i.size=len(b);t.addfile(i,io.BytesIO(b))
 return gzip.compress(out.getvalue())
class Contracts(unittest.TestCase):
 def reject(self,files):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/"part";p.write_bytes(archive(files))
   with self.assertRaises(RuntimeError):zap_snapshot.unpack([str(p)],pathlib.Path(td)/"out")
 def test_traversal(self):self.reject({"../outside":b"x"})
 def test_pin_mismatch(self):self.reject({"manifest.json":json.dumps({"pins":{},"files":{}}).encode()})
 def test_hash_mismatch(self):
  pins={g:{"repository":r,"revision":v} for g,(r,v) in zap_snapshot.PINS.items()}
  self.reject({"x":b"x","manifest.json":json.dumps({"pins":pins,"files":{"x":{"bytes":1,"sha256":"0"*64}}}).encode()})
 def test_partial_and_evidence_redaction(self):
  doc={"target":"https://mithril.fund/","collection_state":"partial","coverage":{"queue_drained":False},
       "counts":{"low":1},"total":1,"limitations":["not full coverage"],"findings":[
       {"rule_id":"10038","severity":"low","title":"Missing header","evidence":"SECRET_BODY","url":"https://mithril.fund/?token=SECRET"}]}
  result=zap_ci.summary("test",doc)
  self.assertEqual(result["collection_state"],"partial")
  self.assertFalse(result["certificate_eligible"])
  self.assertNotIn("SECRET",json.dumps(result))
if __name__=="__main__":unittest.main()

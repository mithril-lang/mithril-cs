"""Context regressions; no network."""
import unittest
from review_2487 import context_and_disposition,Resources,safeurl
class ReviewTests(unittest.TestCase):
 def check(self,body,ctype="text/html"):
  return context_and_disposition("https://example.test/",{"body":body,"headers":{"content-type":ctype}},{"rule-id":"40049","title":"Mixed content","evidence":"http://w"})
 def test_namespace_only(self):
  self.assertEqual("suppressed",self.check('<svg xmlns="http://www.w3.org/2000/svg"/>')["disposition"])
 def test_dynamic_is_not_cleared(self):
  self.assertEqual("deferred",self.check('fetch("http://example.test/api")',"application/javascript")["disposition"])
 def test_svg_fetch_is_retained(self):
  self.assertEqual("deferred",self.check('<svg><use href="http://example.test/i.svg"/></svg>',"image/svg+xml")["disposition"])
 def test_literal_ip_survives(self):
  r=context_and_disposition("https://example.test/",{"body":"host 10.0.0.1","headers":{}},{"rule-id":"40040","title":"Internal IP","evidence":"10.0.0.1"})
  self.assertEqual("deferred",r["disposition"])
 def test_coordinate_false_positive(self):
  r=context_and_disposition("https://example.test/",{"body":"10 20 30 40","headers":{}},{"rule-id":"40040","title":"Internal IP","evidence":"10 20 30 40"})
  self.assertEqual("suppressed",r["disposition"])
 def test_sensitive_url_redaction(self):
  self.assertNotIn("privatevalue",safeurl("https://example.test/?token=privatevalue&lang=en"))
if __name__=="__main__":unittest.main()

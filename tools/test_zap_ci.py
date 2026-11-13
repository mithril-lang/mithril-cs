"""Report safety contracts. 403 collection is never application acceptance."""
import json,unittest
from zap_ci import summary
class Reports(unittest.TestCase):
 def doc(self,status):
  return {"target":"https://mithril.fund/","collection_state":"complete","coverage":{"fetched_pages":1},
          "http_status_counts":{str(status):1},"counts":{"low":1},"total":1,"limitations":["bounded response"],
          "findings":[{"rule_id":"10038","severity":"low","title":"Missing header","evidence":"SECRET_BODY","url":"https://mithril.fund/?token=SECRET"}]}
 def test_403_is_access_blocked_and_redacted(self):
  result=summary("company",self.doc(403))
  self.assertEqual(result["assessment_status"],"access-blocked")
  self.assertEqual(result["application_security"],"UNKNOWN")
  self.assertEqual(result["collection_state"],"complete")
  self.assertFalse(result["certificate_eligible"])
  self.assertNotIn("SECRET",json.dumps(result))
 def test_200_is_response_analysis_not_security_clearance(self):
  result=summary("control",self.doc(200))
  self.assertEqual(result["assessment_status"],"response-analyzed")
  self.assertEqual(result["findings_applies_to"],"received-response-only")
  self.assertEqual(result["application_security"],"UNKNOWN")
if __name__=="__main__":unittest.main()

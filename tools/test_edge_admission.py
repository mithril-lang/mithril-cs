"""Owner-controller pure accounting regressions; no cluster or filesystem writes."""
import datetime,unittest
from vke_verify import owned_memory_credit,GIB
class MemoryBudget(unittest.TestCase):
 def sample(self,uid="owned",used=123,age=0):
  return {"pods":[{"podRef":{"uid":uid},"memory":{"workingSetBytes":used,"time":datetime.datetime.fromtimestamp(1000-age,datetime.timezone.utc).isoformat()}}]}
 def test_no_credit_before_ownership(self):
  self.assertEqual(0,owned_memory_credit(self.sample(),None,1000))
 def test_exact_measured_bytes_only(self):
  self.assertEqual(123,owned_memory_credit(self.sample(),"owned",1000))
 def test_foreign_uid_rejected(self):
  with self.assertRaises(RuntimeError):owned_memory_credit(self.sample("foreign"),"owned",1000)
 def test_stale_rejected(self):
  with self.assertRaises(RuntimeError):owned_memory_credit(self.sample(age=31),"owned",1000)
 def test_over_fixed_limit_rejected(self):
  with self.assertRaises(RuntimeError):owned_memory_credit(self.sample(used=GIB+1),"owned",1000)
 def test_duplicate_uid_rejected(self):
  v=self.sample();v["pods"]*=2
  with self.assertRaises(RuntimeError):owned_memory_credit(v,"owned",1000)
 def test_foreign_reservation_and_margin_retained(self):
  used=int(.8*GIB);free=int(5.2*GIB);self.assertGreaterEqual(free+used,6*GIB-1)
  self.assertGreaterEqual(free,4*GIB+GIB)
  self.assertLess(int(4.9*GIB)+GIB,6*GIB)
if __name__=="__main__":unittest.main()

"""Owner-controller pure accounting regressions; no cluster or filesystem writes."""
import datetime,unittest
from vke_verify import owned_memory_credit,dedicated_node_lease,GIB
class MemoryBudget(unittest.TestCase):
 def sample(self,uid="owned",used=123,age=0):
  return {"node":{"memory":{"time":datetime.datetime.fromtimestamp(1000,datetime.timezone.utc).isoformat()}},"pods":[{"podRef":{"uid":uid},"memory":{"workingSetBytes":used,"time":datetime.datetime.fromtimestamp(1000-age,datetime.timezone.utc).isoformat()}}]}
 def test_no_credit_before_ownership(self):
  self.assertEqual(0,owned_memory_credit(self.sample(),None,1000))
 def test_exact_measured_bytes_only(self):
  self.assertEqual(123,owned_memory_credit(self.sample(),"owned",1000))
 def test_foreign_uid_rejected(self):
  with self.assertRaises(RuntimeError):owned_memory_credit(self.sample("foreign"),"owned",1000)
 def test_stale_rejected(self):
  with self.assertRaises(RuntimeError):owned_memory_credit(self.sample(age=31),"owned",1000)
 def test_asynchronous_timestamps_rejected(self):
  with self.assertRaises(RuntimeError):owned_memory_credit(self.sample(age=9),"owned",1000)
 def test_over_fixed_limit_rejected(self):
  with self.assertRaises(RuntimeError):owned_memory_credit(self.sample(used=GIB+1),"owned",1000)
 def test_duplicate_uid_rejected(self):
  v=self.sample();v["pods"]*=2
  with self.assertRaises(RuntimeError):owned_memory_credit(v,"owned",1000)
 def test_smaller_allocation_rejects_larger_credit(self):
  with self.assertRaises(RuntimeError):owned_memory_credit(self.sample(used=769*1024*1024),"owned",1000,768*1024*1024)
 def test_smaller_allocation_keeps_foreign_reservation_and_margin(self):
  allocation=768*1024*1024;required=5*GIB+allocation
  used=400*1024*1024;free=required-used
  self.assertEqual(used,owned_memory_credit(self.sample(used=used),"owned",1000,allocation))
  self.assertEqual(free,4*GIB+GIB+(allocation-used))
 def test_foreign_reservation_and_margin_retained(self):
  used=int(.8*GIB);free=int(5.2*GIB);self.assertGreaterEqual(free+used,6*GIB-1)
  self.assertGreaterEqual(free,4*GIB+GIB)
  self.assertLess(int(4.9*GIB)+GIB,6*GIB)
class DedicatedCapacity(unittest.TestCase):
 def fixture(self):
  uid="12345678-1234-1234-1234-123456789012";name="ci-cs-capacity-20261114-example"
  node={"metadata":{"name":name,"uid":uid,"labels":{"mithril.fund/owner":"MITHRIL-2527"}},"spec":{"providerID":"vultr://87654321-1234-1234-1234-123456789012","taints":[{"key":"mithril.fund/execution-lane","value":"ci-profile","effect":"NoSchedule"}]}}
  policy={"issue":"MITHRIL-2527","approved":True,"original_nodes":{"held":"old-uid"},"node":{"name":name,"uid":uid,"provider_id":node["spec"]["providerID"]}}
  return policy,node,{"held":"old-uid",name:uid}
 def test_additional_node_has_independent_uid_lock(self):
  p,n,r=self.fixture();self.assertEqual("mithril-cs-node-"+n["metadata"]["uid"],dedicated_node_lease(p,n,r))
 def test_existing_held_node_cannot_change_locks(self):
  p,n,r=self.fixture();p["original_nodes"][n["metadata"]["name"]]=n["metadata"]["uid"]
  with self.assertRaises(RuntimeError):dedicated_node_lease(p,n,r)
 def test_foreign_original_change_rejected(self):
  p,n,r=self.fixture();r["held"]="different"
  with self.assertRaises(RuntimeError):dedicated_node_lease(p,n,r)
 def test_no_taint_rejected(self):
  p,n,r=self.fixture();n["spec"]["taints"]=[]
  with self.assertRaises(RuntimeError):dedicated_node_lease(p,n,r)
 def test_wrong_provider_rejected(self):
  p,n,r=self.fixture();n["spec"]["providerID"]="vultr://00000000-0000-0000-0000-000000000000"
  with self.assertRaises(RuntimeError):dedicated_node_lease(p,n,r)
 def test_missing_approval_rejected(self):
  p,n,r=self.fixture();p["approved"]=False
  with self.assertRaises(RuntimeError):dedicated_node_lease(p,n,r)
if __name__=="__main__":unittest.main()

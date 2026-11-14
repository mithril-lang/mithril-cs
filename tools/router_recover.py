"""Bounded same-identity resident recovery. Never enrolls or rotates credentials.
Prepare creates only immutable source/config and a private state backup. Execute
requires the exact journal and tested init digest; old writer is fenced before
same-holder lease/pin reconciliation. Unknown mutations retain the physical slot.
"""
import argparse, base64, contextlib, copy, datetime, hashlib, io, json, re, socket, ssl, subprocess, sys, time, unittest, uuid
from unittest.mock import patch

NS="mithril-ci-router"
LNS="mithril-ci-control"
POD="router-resident-v1-0"
STS="router-resident-v1"
OWNER="mithril-router-owner-v1"
PHYSICAL="mithril-shared-spare-heavy"
PHYSICAL_UID="930d3ec7-328d-4a74-8676-e16f7e8d2fe6"
ARTIFACT="router-init-tini-c5b0666b4cb6"
TINI_SHA="c5b0666b4cb676901f90dfcb37106783c5fe2077b04590973b885950611b30ee"
PREFIX="mithril.fund/"
def need(ok, reason):
    if not ok: raise RuntimeError(reason)
def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def state_proof(secret, policy):
    m=secret["metadata"]; a=m.get("annotations",{})
    need(m["uid"]==policy["state_uid"] and m["namespace"]==NS and m["name"]=="router-state-persistent-v1"
         and not m.get("deletionTimestamp") and bool(secret.get("data")), "state identity or empty")
    e=policy["expected_device"]
    need(a.get(PREFIX+"router-device-id")==e["device_id"] and
         a.get(PREFIX+"router-node-id")==str(e["node_id"]) and
         a.get(PREFIX+"router-ipv4")==e["tailnet_ipv4"],"state device changed")
    return {"uid":m["uid"],"rv":m["resourceVersion"],"data_sha256":digest(secret["data"])}
def diagnostic_source(source):
    old="print('RESIDENT_OWNER_HOLD '+type(error).__name__,file=sys.stderr,flush=True)"
    new="print('RESIDENT_OWNER_HOLD '+json.dumps(failure_metadata(error),sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True)"
    helper="def failure_metadata(error):\n # Source locations only: never exception messages, locals or response bodies.\n frames=[];tb=error.__traceback__\n while tb is not None:\n  name=Path(tb.tb_frame.f_code.co_filename).name\n  if re.fullmatch('[a-z_]+\\.py',name):\n   frames.append({'source':name,'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno})\n  tb=tb.tb_next\n return {'class':type(error).__name__,'module':type(error).__module__,'frames':frames[-12:]}\n\n"
    if source.count(helper)==1 and source.count(new)==1 and old not in source:
        original=source.replace(helper,'',1).replace(new,old,1)
        need(original.count('def main():')==1 and 'def failure_metadata(' not in original,'diagnostic source drift')
        need(original.replace('def main():',helper+'def main():',1).replace(old,new,1)==source,'diagnostic source drift')
        return source
    need(source.count(old)==1 and source.count('def main():')==1 and 'def failure_metadata(' not in source and new not in source,'diagnostic source drift')
    return source.replace('def main():',helper+'def main():').replace(old,new)

def plan_spec(pod, policy, op):
    need(re.fullmatch("[a-f0-9]{32}",op),"recovery operation")
    need(digest(pod["spec"])==policy["pod_spec_sha256"],"old Podspec drift")
    spec=copy.deepcopy(pod["spec"]); new=copy.deepcopy(policy)
    need(not spec.get("ephemeralContainers") and not spec.get("shareProcessNamespace")
         and not spec.get("hostNetwork"),"unexpected isolation")
    tail=next(c for c in spec["containers"] if c["name"]=="tailscale")
    if tail["command"][:3]==["/init/tini","-g","--"]:
        need(tail["command"][3:5]==["/bin/sh","-c"],"unknown initialized watchdog")
        need([m for m in tail.get("volumeMounts",[]) if m.get("name")=="init-reaper"]==[{"name":"init-reaper","mountPath":"/init","readOnly":True}],"init mount drift")
        need([v for v in spec["volumes"] if v.get("name")=="init-reaper"]==[{"name":"init-reaper","configMap":{"name":ARTIFACT,"defaultMode":365}}],"init volume drift")
    else:
        need(tail["command"][:2]==["/bin/sh","-c"],"unknown watchdog command")
        tail["command"]=["/init/tini","-g","--"]+tail["command"]
        tail.setdefault("volumeMounts",[]).append({"name":"init-reaper","mountPath":"/init","readOnly":True})
        spec["volumes"].append({"name":"init-reaper","configMap":{"name":ARTIFACT,"defaultMode":365}})
    policy_name="router-recovery-policy-"+op[:12]; pin_name="router-recovery-pin-"+op[:12]
    for volume in spec["volumes"]:
        if volume["name"]=="resident-policy": volume["configMap"]["name"]=policy_name
    old_pin=next(e["valueFrom"]["configMapKeyRef"]["name"] for c in spec["containers"] if c["name"]=="router-owner"
                 for e in c["env"] if e["name"]=="RESIDENT_POLICY_SHA256")
    for c in spec["containers"]:
        for e in c.get("env",[]):
            ref=e.get("valueFrom",{}).get("configMapKeyRef")
            if ref and ref["name"]==old_pin: ref["name"]=pin_name
    new["pod_spec_sha256"]=digest(spec)
    return spec,new,policy_name,pin_name
def lease_recovery_patch(lease, old_policy, new_policy_sha, *, fenced, expected_pin, new_source=None):
    need(fenced is True,"old writer must be fenced")
    a=lease["metadata"].get("annotations",{})
    need(lease["metadata"]["uid"]==old_policy["owner_lease_uid"] and
         lease["spec"]["holderIdentity"]==old_policy["operation"] and
         a.get(PREFIX+"source-sha256")==old_policy["source_sha256"] and
         a.get(PREFIX+"pin-sha256")==expected_pin and a.get(PREFIX+"operation")==old_policy["operation"] and
         a.get(PREFIX+"node-uid")==old_policy["node_uid"],"owner changed")
    updated=copy.deepcopy(a); updated[PREFIX+"pin-sha256"]=new_policy_sha
    updated[PREFIX+"source-sha256"]=new_source or old_policy["source_sha256"]
    return [{"op":"test","path":"/metadata/uid","value":lease["metadata"]["uid"]},
            {"op":"test","path":"/metadata/resourceVersion","value":lease["metadata"]["resourceVersion"]},
            {"op":"test","path":"/spec/holderIdentity","value":old_policy["operation"]},
            {"op":"test","path":"/metadata/annotations","value":a},
            {"op":"replace","path":"/metadata/annotations","value":updated},
            {"op":"replace","path":"/spec/renewTime","value":stamp()}]

class Operator:
    def __init__(self,args):
        self.args=args
        self.k=["kubectl","--kubeconfig",args.kubeconfig,"--request-timeout=12s"]
    def call(self,argv,body=None):
        r=subprocess.run(self.k+argv,input=json.dumps(body) if body is not None else None,
                         capture_output=True,text=True,timeout=20)
        need(r.returncode==0,"provider request failed; reconcile before retry")
        return json.loads(r.stdout) if r.stdout.strip() else None
    def get(self,kind,name,ns=NS,absent=False):
        return self.call(["get",kind,name,"-n",ns,"-o","json"]+(["--ignore-not-found=true"] if absent else []))
    def create(self,obj):
        need(self.get(obj["kind"],obj["metadata"]["name"],obj["metadata"].get("namespace",NS),True) is None,"object exists")
        actual=self.call(["create","-f","-","-o","json"],obj)
        reread=self.get(obj["kind"],obj["metadata"]["name"],obj["metadata"].get("namespace",NS))
        need(actual["metadata"]["uid"]==reread["metadata"]["uid"],"create outcome unknown")
        return reread
    def ensure_code(self,name,data):
        existing=self.get("ConfigMap",name,NS,True)
        if existing is None:
            existing=self.create({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":name,"namespace":NS},"immutable":True,"data":data})
        need(existing.get("immutable") is True and existing.get("data")==data and not existing.get("binaryData") and not existing["metadata"].get("deletionTimestamp"),"existing code differs or is mutable")
        return existing
    def save(self,journal,phase,**values):
        old=self.get("ConfigMap",journal)
        data=json.loads(old["data"]["plan"])
        data.update(values);data["phase"]=phase
        old["data"]["plan"]=json.dumps(data,sort_keys=True,separators=(",",":"))
        ack=self.call(["replace","-f","-","-o","json"],old)
        need(ack["metadata"]["uid"]==old["metadata"]["uid"],"journal changed")
        return data
    def physical(self,plan,action):
        x=self.get("Lease",PHYSICAL,LNS)
        need(x["metadata"]["uid"]==PHYSICAL_UID,"physical lease changed")
        a=x["metadata"].get("annotations",{}); spec=x["spec"]
        if action=="claim":
            need(not spec.get("holderIdentity") and a.get(PREFIX+"phase")=="idle","physical not idle")
        else:
            need(spec.get("holderIdentity")==plan["recovery_operation"] and a.get(PREFIX+"recovery-journal")==plan["journal"],"physical owner changed")
        desired=copy.deepcopy(spec); annotations=copy.deepcopy(a)
        if action=="claim":
            desired.update(holderIdentity=plan["recovery_operation"],leaseDurationSeconds=90,renewTime=stamp(),acquireTime=stamp())
            annotations.update({PREFIX+"phase":"resident-recovery",PREFIX+"recovery-journal":plan["journal"],PREFIX+"recovery-source":plan["source_revision"]})
        elif action=="renew": desired["renewTime"]=stamp()
        elif action=="release":
            desired["holderIdentity"]="";desired["renewTime"]=stamp()
            annotations.update({PREFIX+"phase":"idle",PREFIX+"resident-commit-pod-uid":plan["new_pod_uid"],
                                PREFIX+"resident-policy-sha256":plan["new_policy_sha256"],
                                PREFIX+"resident-pod-spec-sha256":plan["new_policy"]["pod_spec_sha256"]})
        patch=[{"op":"test","path":"/metadata/uid","value":PHYSICAL_UID},
               {"op":"test","path":"/metadata/resourceVersion","value":x["metadata"]["resourceVersion"]},
               {"op":"test","path":"/spec","value":spec},
               {"op":"replace","path":"/metadata/annotations","value":annotations},
               {"op":"replace","path":"/spec","value":desired}]
        self.call(["patch","lease",PHYSICAL,"-n",LNS,"--type=json","--patch-file","/dev/stdin","-o","json"],patch)
        actual=self.get("Lease",PHYSICAL,LNS)
        need(actual["spec"]==desired and actual["metadata"]["annotations"]==annotations,"physical CAS unknown")
        return actual
    def scale(self,plan,replicas):
        sts=self.get("StatefulSet",STS)
        need(sts["metadata"]["uid"]==plan["controller_uid"],"controller changed")
        patch=[{"op":"test","path":"/metadata/uid","value":plan["controller_uid"]},
               {"op":"test","path":"/metadata/resourceVersion","value":sts["metadata"]["resourceVersion"]},
               {"op":"replace","path":"/spec/replicas","value":replicas}]
        self.call(["patch","statefulset",STS,"-n",NS,"--type=json","--patch-file","/dev/stdin","-o","json"],patch)
        need(self.get("StatefulSet",STS)["spec"]["replicas"]==replicas,"scale unknown")
    def prepare(self):
        pod=self.get("Pod",POD);sts=self.get("StatefulSet",STS)
        need(pod["metadata"]["uid"]==self.args.expected_pod_uid and sts["spec"]["replicas"]==1,"unexpected current writer")
        policy_volume=next(v for v in pod["spec"]["volumes"] if v["name"]=="resident-policy")
        old_policy_cm=self.get("ConfigMap",policy_volume["configMap"]["name"])
        old_raw=old_policy_cm["data"]["policy.json"]; old=json.loads(old_raw)
        need(old["controller_uid"]==sts["metadata"]["uid"] and old["pod_name"]==POD,"owner policy")
        code=self.get("ConfigMap",next(v for v in pod["spec"]["volumes"] if v["name"]=="owner-code")["configMap"]["name"])
        need(code.get("immutable") is True and digest(old["source_files"])==old["source_sha256"],"source manifest")
        need(all(hashlib.sha256(code["data"][n].encode()).hexdigest()==sha for n,sha in old["source_files"].items()),"source drift")
        init=self.get("ConfigMap",ARTIFACT)
        need(init.get("immutable") is True and hashlib.sha256(base64.b64decode(init["binaryData"]["tini"])).hexdigest()==TINI_SHA,"init artifact")
        state=self.get("Secret","router-state-persistent-v1"); proof=state_proof(state,old)
        nodes=self.call(["get","--raw","/api/v1/nodes?limit=2000"])
        need(nodes.get("kind")=="NodeList" and not nodes["metadata"].get("continue") and len(nodes["items"])==4,"node inventory")
        roster={n["metadata"]["name"]:n["metadata"]["uid"] for n in nodes["items"]}
        op=uuid.uuid4().hex;spec,new,policy_name,pin_name=plan_spec(pod,old,op)
        # Preserve the original closed runtime and all adapted byte pins; change
        # only its bounded source-location reporter, then bind the new manifest.
        source_data=copy.deepcopy(code["data"])
        source_data["resident_owner_entrypoint.py"]=diagnostic_source(source_data["resident_owner_entrypoint.py"])
        new["source_files"]={name:hashlib.sha256(body.encode()).hexdigest() for name,body in source_data.items()}
        new["source_sha256"]=digest(new["source_files"])
        code_name="router-resident-code-"+new["source_sha256"][:16]
        for volume in spec["volumes"]:
            if volume["name"]=="owner-code":volume["configMap"]["name"]=code_name
        for c in spec["containers"]:
            for e in c.get("env",[]):
                if e["name"]=="OWNER_SOURCE_SHA256":e["value"]=new["source_sha256"]
        new["pod_spec_sha256"]=digest(spec)
        raw=json.dumps(new,sort_keys=True,separators=(",",":"))
        policy_sha=hashlib.sha256(raw.encode()).hexdigest()
        journal="router-recovery-"+op[:12]
        plan={"schema":"router-pid1-recovery-v1","phase":"prepared","journal":journal,"recovery_operation":op,
              "source_revision":self.args.source,"created_at":stamp(),"old_pod_uid":pod["metadata"]["uid"],
              "controller_uid":sts["metadata"]["uid"],"old_template":sts["spec"]["template"],
              "old_policy":old,"old_policy_sha256":hashlib.sha256(old_raw.encode()).hexdigest(),
              "old_state":proof,"node_roster":roster,"new_spec":spec,"new_policy":new,"new_policy_name":policy_name,
              "new_pin_name":pin_name,"new_policy_sha256":policy_sha,"init_sha256":TINI_SHA}
        backup_name=journal+"-state"
        backup={"apiVersion":"v1","kind":"Secret","metadata":{"name":backup_name,"namespace":NS,
                "labels":{"mithril.fund/owner":"MITHRIL-2327"},"annotations":{"mithril.fund/source-state-uid":proof["uid"],"mithril.fund/data-sha256":proof["data_sha256"]}},
                "type":state.get("type","Opaque"),"immutable":True,"data":state["data"]}
        b=self.create(backup)
        need(b.get("immutable") is True and digest(b["data"])==proof["data_sha256"],"backup verification")
        need(state_proof(self.get("Secret","router-state-persistent-v1"),old)==proof,"state changed before freeze")
        plan["backup"]={"name":backup_name,"uid":b["metadata"]["uid"],"data_sha256":proof["data_sha256"]}
        self.ensure_code(code_name,source_data)
        self.create({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":policy_name,"namespace":NS},"immutable":True,"data":{"policy.json":raw}})
        self.create({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":pin_name,"namespace":NS},"immutable":True,"data":{"policy_sha256":policy_sha}})
        self.create({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":journal,"namespace":NS},"data":{"plan":json.dumps(plan,sort_keys=True,separators=(",",":"))}})
        print(json.dumps({"journal":journal,"phase":"prepared","old_pod_uid":plan["old_pod_uid"],
                          "backup_uid":b["metadata"]["uid"],"state_sha256":proof["data_sha256"],
                          "new_policy_sha256":policy_sha,"new_spec_sha256":new["pod_spec_sha256"]}),flush=True)
    def execute(self):
        plan=json.loads(self.get("ConfigMap",self.args.journal)["data"]["plan"])
        need(plan["phase"]=="prepared" and plan["source_revision"]==self.args.source,"plan/source/phase changed")
        need(self.get("Pod",POD)["metadata"]["uid"]==plan["old_pod_uid"],"old writer changed")
        node=self.call(["get","node",plan["old_policy"]["node_name"],"-o","json"])
        conditions={c["type"]:c["status"] for c in node["status"]["conditions"]}
        need(node["metadata"]["uid"]==plan["old_policy"]["node_uid"] and conditions["Ready"]=="True"
             and all(conditions[k]=="False" for k in ["MemoryPressure","DiskPressure","PIDPressure"]),"node hold")
        state=self.get("Secret","router-state-persistent-v1")
        need(state_proof(state,plan["old_policy"])==plan["old_state"],"state drift")
        b=self.get("Secret",plan["backup"]["name"])
        need(b["metadata"]["uid"]==plan["backup"]["uid"] and digest(b["data"])==plan["old_state"]["data_sha256"],"backup changed")
        nodes=self.call(["get","--raw","/api/v1/nodes?limit=2000"])
        need(nodes.get("kind")=="NodeList" and not nodes["metadata"].get("continue") and
             {n["metadata"]["name"]:n["metadata"]["uid"] for n in nodes["items"]}==plan["node_roster"],"node roster changed")
        stats=self.call(["get","--raw","/api/v1/nodes/"+plan["old_policy"]["node_name"]+"/proxy/stats/summary"])["node"]
        need(stats["memory"]["availableBytes"]>=1536*1024**2 and stats["fs"]["availableBytes"]>=16*1024**3,"recovery headroom")
        self.physical(plan,"claim")
        self.save(plan["journal"],"quiesce-intent")
        self.scale(plan,0)
        end=time.monotonic()+150;renew=time.monotonic()
        while self.get("Pod",POD,absent=True) is not None:
            need(time.monotonic()<end,"old writer drain unknown")
            if time.monotonic()-renew>=20:self.physical(plan,"renew");renew=time.monotonic()
            time.sleep(2)
        need(self.get("StatefulSet",STS)["spec"]["replicas"]==0,"writer not fenced")
        need(state_proof(self.get("Secret","router-state-persistent-v1"),plan["old_policy"])==plan["old_state"],"drain state changed")
        self.save(plan["journal"],"old-writer-fenced")
        lease=self.get("Lease",OWNER,LNS)
        patch=lease_recovery_patch(lease,plan["old_policy"],plan["new_policy_sha256"],fenced=True,expected_pin=plan["old_policy_sha256"],new_source=plan["new_policy"]["source_sha256"])
        self.call(["patch","lease",OWNER,"-n",LNS,"--type=json","--patch-file","/dev/stdin","-o","json"],patch)
        self.save(plan["journal"],"same-holder-reconciled")
        current=self.get("StatefulSet",STS);template=copy.deepcopy(plan["old_template"]);template["spec"]=plan["new_spec"]
        self.call(["patch","statefulset",STS,"-n",NS,"--type=json","--patch-file","/dev/stdin","-o","json"],
                  [{"op":"test","path":"/metadata/uid","value":plan["controller_uid"]},
                   {"op":"test","path":"/metadata/resourceVersion","value":current["metadata"]["resourceVersion"]},
                   {"op":"test","path":"/spec/replicas","value":0},
                   {"op":"replace","path":"/spec/template","value":template}])
        # Refresh once while no worker can run; never race the worker's renewal.
        lease=self.get("Lease",OWNER,LNS);updated=copy.deepcopy(plan["new_policy"])
        patch=lease_recovery_patch(lease,updated,plan["new_policy_sha256"],fenced=True,expected_pin=plan["new_policy_sha256"])
        self.call(["patch","lease",OWNER,"-n",LNS,"--type=json","--patch-file","/dev/stdin","-o","json"],patch)
        self.save(plan["journal"],"new-writer-start-intent")
        self.scale(plan,1);end=time.monotonic()+150;renew=time.monotonic()
        while time.monotonic()<end:
            if time.monotonic()-renew>=20:self.physical(plan,"renew");renew=time.monotonic()
            pod=self.get("Pod",POD,absent=True)
            if pod:
                need(pod["metadata"]["uid"]!=plan["old_pod_uid"] and digest(pod["spec"])==plan["new_policy"]["pod_spec_sha256"],"new Podspec drift")
                if pod.get("status",{}).get("containerStatuses") and all(s.get("ready") is True for s in pod["status"]["containerStatuses"]):
                    plan["new_pod_uid"]=pod["metadata"]["uid"]
                    need(len(pod["status"]["containerStatuses"])==2 and all(s.get("restartCount")==0 for s in pod["status"]["containerStatuses"]),"new runtime restarted")
                    self.save(plan["journal"],"ready-awaiting-native-api",new_pod_uid=plan["new_pod_uid"])
                    print(json.dumps({"journal":plan["journal"],"phase":"ready-awaiting-native-api","new_pod_uid":plan["new_pod_uid"]}),flush=True);return
            time.sleep(2)
        self.save(plan["journal"],"held-new-readiness-unknown")
        raise RuntimeError("new writer readiness unknown; retain physical lease and backup")
    def commit(self):
        plan=json.loads(self.get("ConfigMap",self.args.journal)["data"]["plan"])
        need(plan["phase"]=="ready-awaiting-native-api","native recovery phase")
        pod=self.get("Pod",POD);need(pod["metadata"]["uid"]==plan["new_pod_uid"] and
            all(s.get("ready") is True and s.get("restartCount")==0 for s in pod["status"]["containerStatuses"]),"runtime changed")
        r=subprocess.run(self.k+["--server=https://100.92.127.42:6443",
            "--tls-server-name=17f3e901-5f9e-4928-9115-b2e8a2446f25.vultr-k8s.com","get","nodes","-o","json"],
            capture_output=True,text=True,timeout=20)
        need(r.returncode==0,"native API not verified")
        nodes=json.loads(r.stdout)
        need({n["metadata"]["name"]:n["metadata"]["uid"] for n in nodes.get("items",[])}==plan["node_roster"],"native node roster")
        config=json.loads(subprocess.check_output(self.k+["config","view","--raw","-o","json"],text=True))
        cluster=config["clusters"][0]["cluster"];ca=base64.b64decode(cluster["certificate-authority-data"])
        need(hashlib.sha256(ca).hexdigest()=="10c49e3b468d79f556b84be06d21a551b2ecbace449844359da5e16e696eba67","original CA")
        ctx=ssl.create_default_context(cadata=ca.decode())
        for auth,expected in [("",403),("Bearer deliberately-invalid",401)]:
            raw=socket.create_connection(("100.92.127.42",6443),5);raw.settimeout(8)
            with ctx.wrap_socket(raw,server_hostname="17f3e901-5f9e-4928-9115-b2e8a2446f25.vultr-k8s.com") as tls:
                headers="Authorization: "+auth+"\r\n" if auth else ""
                tls.sendall(("GET /api/v1/nodes HTTP/1.1\r\nHost: 17f3e901-5f9e-4928-9115-b2e8a2446f25.vultr-k8s.com\r\n"+headers+"Connection: close\r\n\r\n").encode())
                status=int(tls.recv(4096).split(b" ",2)[1]);need(status==expected,"native authorization denial mismatch")
        old=self.get("Lease",OWNER,LNS);deadline=time.monotonic()+35
        new=old
        while time.monotonic()<deadline and old["spec"]["renewTime"]==new["spec"]["renewTime"]:
            time.sleep(2);new=self.get("Lease",OWNER,LNS)
        need(new["metadata"]["uid"]==plan["old_policy"]["owner_lease_uid"] and
             new["spec"]["holderIdentity"]==plan["old_policy"]["operation"] and
             old["spec"]["renewTime"]!=new["spec"]["renewTime"],"worker renewal missing")
        state_proof(self.get("Secret","router-state-persistent-v1"),plan["old_policy"])
        self.save(plan["journal"],"native-api-qualified",native_node_uids={n["metadata"]["name"]:n["metadata"]["uid"] for n in nodes["items"]})
        self.physical(plan,"release")
        self.save(plan["journal"],"committed-physical-idle")
        print(json.dumps({"journal":plan["journal"],"phase":"committed-physical-idle","new_pod_uid":plan["new_pod_uid"],
                          "same_state_uid":plan["old_state"]["uid"],"same_owner_operation":plan["old_policy"]["operation"]}),flush=True)

class Contracts(unittest.TestCase):
    def fixture(self):
        spec={"containers":[{"name":"tailscale","command":["/bin/sh","-c","original"],"volumeMounts":[]},
              {"name":"router-owner","env":[{"name":"RESIDENT_POLICY_SHA256","valueFrom":{"configMapKeyRef":{"name":"old","key":"policy_sha256"}}}]}],
              "volumes":[{"name":"resident-policy","configMap":{"name":"old-policy"}}]}
        pod={"spec":spec};policy={"pod_spec_sha256":digest(spec),"state_uid":"state","operation":"a"*32,
             "owner_lease_uid":"lease","node_uid":"node","source_sha256":"b"*64,"expected_device":{"device_id":"d","node_id":1,"tailnet_ipv4":"100.1.2.3"}}
        return pod,policy
    def test_spec_and_source_preserved(self):
        pod,p=self.fixture();original=copy.deepcopy(pod)
        spec,new,_,_=plan_spec(pod,p,"c"*32)
        self.assertEqual(pod,original);self.assertEqual(new["source_sha256"],p["source_sha256"])
        self.assertEqual(spec["containers"][0]["command"][3:],pod["spec"]["containers"][0]["command"])
        self.assertNotEqual(new["pod_spec_sha256"],p["pod_spec_sha256"])
    def test_initialized_recovery_preserves_tini(self):
        pod,p=self.fixture();spec,new,_,_=plan_spec(pod,p,"c"*32)
        again,_,_,_=plan_spec({"spec":spec},new,"d"*32)
        self.assertEqual(again["containers"][0]["command"],spec["containers"][0]["command"])
        self.assertEqual(len([v for v in again["volumes"] if v["name"]=="init-reaper"]),1)
    def test_initialized_recovery_rejects_mount_drift(self):
        pod,p=self.fixture();spec,new,_,_=plan_spec(pod,p,"c"*32)
        spec["containers"][0]["volumeMounts"][0]["readOnly"]=False
        new["pod_spec_sha256"]=digest(spec)
        with self.assertRaises(RuntimeError):plan_spec({"spec":spec},new,"d"*32)
    def test_diagnostic_never_includes_error_text(self):
        source="import json,re\nfrom pathlib import Path\ndef main():\n try: raise RuntimeError('CREDENTIAL_SENTINEL')\n except Exception as error:\n  print('RESIDENT_OWNER_HOLD '+type(error).__name__,file=sys.stderr,flush=True)\n"
        updated=diagnostic_source(source);ns={};exec(compile(updated,'resident_owner_entrypoint.py','exec'),ns)
        try:raise RuntimeError('CREDENTIAL_SENTINEL')
        except Exception as e:result=ns['failure_metadata'](e)
        self.assertNotIn('CREDENTIAL_SENTINEL',json.dumps(result))
        self.assertEqual(result['class'],'RuntimeError')
        self.assertEqual(diagnostic_source(updated),updated)
        with self.assertRaises(RuntimeError):diagnostic_source(updated.replace('frames[-12:]','frames[-13:]'))
        with self.assertRaises(RuntimeError):diagnostic_source(updated+'\ndef failure_metadata(error): pass\n')
    def test_existing_code_is_reused_only_if_exact_and_immutable(self):
        class Fake(Operator):
            def __init__(self,obj):self.obj=obj
            def get(self,*args):return self.obj
            def create(self,obj):self.obj=obj;return obj
        data={'resident_owner_entrypoint.py':'source'}
        op=Fake(None); first=op.ensure_code('source-name',data)
        self.assertIs(op.ensure_code('source-name',data),first)
        for change in ({'immutable':False},{'data':{'resident_owner_entrypoint.py':'other'}},{'binaryData':{'extra':'YQ=='}}):
            altered=copy.deepcopy(first);altered.update(change)
            with self.assertRaises(RuntimeError):Fake(altered).ensure_code('source-name',data)
        class Unknown(Fake):
            def create(self,obj):
                self.obj=obj
                raise RuntimeError('create outcome unknown')
        with self.assertRaisesRegex(RuntimeError,'outcome unknown'):Unknown(None).ensure_code('source-name',data)
    def test_prepare_again_with_installed_diagnostics(self):
        source="def main():\n try: pass\n except Exception as error:\n  print('RESIDENT_OWNER_HOLD '+type(error).__name__,file=sys.stderr,flush=True)\n"
        data={'resident_owner_entrypoint.py':diagnostic_source(source)}
        files={n:hashlib.sha256(v.encode()).hexdigest() for n,v in data.items()}
        source_sha=digest(files); code_name='router-resident-code-'+source_sha[:16]
        pod,p=self.fixture()
        pod['spec']['volumes'].append({'name':'owner-code','configMap':{'name':code_name}})
        pod['spec']['containers'][1]['env'].append({'name':'OWNER_SOURCE_SHA256','value':source_sha})
        p.update(pod_spec_sha256=digest(pod['spec']),source_files=files,source_sha256=source_sha,controller_uid='controller',pod_name=POD)
        initialized,p,_,_=plan_spec(pod,p,'c'*32)
        pod={'metadata':{'uid':'pod'},'spec':initialized}
        policy_name=next(v['configMap']['name'] for v in initialized['volumes'] if v['name']=='resident-policy')
        state={'metadata':{'name':'router-state-persistent-v1','namespace':NS,'uid':'state','resourceVersion':'1','annotations':{PREFIX+'router-device-id':'d',PREFIX+'router-node-id':'1',PREFIX+'router-ipv4':'100.1.2.3'}},'data':{'x':'synthetic'}}
        tini=b'fixture-tini'
        class Fake(Operator):
            def __init__(self):
                self.args=argparse.Namespace(expected_pod_uid='pod',source='fixture')
                self.objects={('Pod',POD):pod,('StatefulSet',STS):{'metadata':{'uid':'controller'},'spec':{'replicas':1,'template':{'spec':initialized}}},('ConfigMap',policy_name):{'data':{'policy.json':json.dumps(p)}},('ConfigMap',code_name):{'metadata':{'uid':'code'},'immutable':True,'data':data},('ConfigMap',ARTIFACT):{'immutable':True,'binaryData':{'tini':base64.b64encode(tini).decode()}},('Secret','router-state-persistent-v1'):state}
            def get(self,kind,name,ns=NS,absent=False):return copy.deepcopy(self.objects.get((kind,name)))
            def create(self,obj):
                key=(obj['kind'],obj['metadata']['name']);need(key not in self.objects,'object exists')
                obj=copy.deepcopy(obj);obj['metadata']['uid']='fixture-'+str(len(self.objects));self.objects[key]=obj;return copy.deepcopy(obj)
            def call(self,*args):return {'kind':'NodeList','metadata':{},'items':[{'metadata':{'name':str(i),'uid':str(i)}} for i in range(4)]}
        op=Fake()
        with patch.object(sys.modules[__name__],'TINI_SHA',hashlib.sha256(tini).hexdigest()), contextlib.redirect_stdout(io.StringIO()):op.prepare()
        plans=[json.loads(v['data']['plan']) for (kind,name),v in op.objects.items() if kind=='ConfigMap' and name.startswith('router-recovery-') and 'plan' in v.get('data',{})]
        self.assertEqual(len(plans),1)
        self.assertEqual(plans[0]['new_policy']['source_sha256'],source_sha)
        self.assertEqual(op.objects[('ConfigMap',code_name)]['data'],data)
        self.assertEqual(plans[0]['phase'],'prepared')
    def test_new_source_binding_only_after_fencing(self):
        _,p=self.fixture();lease={"metadata":{"uid":"lease","resourceVersion":"1","annotations":{PREFIX+"source-sha256":"b"*64,PREFIX+"pin-sha256":"e"*64,PREFIX+"node-uid":"node",PREFIX+"operation":"a"*32}},"spec":{"holderIdentity":"a"*32}}
        patch=lease_recovery_patch(lease,p,"d"*64,fenced=True,expected_pin="e"*64,new_source="f"*64)
        self.assertEqual(next(v['value'] for v in patch if v['path']=='/metadata/annotations' and v['op']=='replace')[PREFIX+'source-sha256'],'f'*64)
        with self.assertRaises(RuntimeError):lease_recovery_patch(lease,p,"d"*64,fenced=False,expected_pin="e"*64,new_source="f"*64)
    def test_source_drift_rejected(self):
        pod,p=self.fixture();pod["spec"]["hostNetwork"]=True
        with self.assertRaises(RuntimeError):plan_spec(pod,p,"c"*32)
    def test_fencing_required(self):
        _,p=self.fixture()
        with self.assertRaises(RuntimeError):lease_recovery_patch({},p,"d"*64,fenced=False,expected_pin="e"*64)
    def test_same_holder_only(self):
        _,p=self.fixture()
        lease={"metadata":{"uid":"lease","resourceVersion":"1","annotations":{PREFIX+"source-sha256":"b"*64,PREFIX+"pin-sha256":"e"*64,PREFIX+"node-uid":"node",PREFIX+"operation":"a"*32}},
               "spec":{"holderIdentity":"a"*32}}
        patch=lease_recovery_patch(lease,p,"d"*64,fenced=True,expected_pin="e"*64)
        self.assertFalse(any(v["path"]=="/spec/holderIdentity" and v["op"]!="test" for v in patch))
        lease["spec"]["holderIdentity"]="foreign"
        with self.assertRaises(RuntimeError):lease_recovery_patch(lease,p,"d"*64,fenced=True,expected_pin="e"*64)
    def test_state_rejects_empty_and_different_identity(self):
        _,p=self.fixture()
        secret={"metadata":{"name":"router-state-persistent-v1","namespace":NS,"uid":"state","resourceVersion":"1",
                "annotations":{PREFIX+"router-device-id":"d",PREFIX+"router-node-id":"1",PREFIX+"router-ipv4":"100.1.2.3"}},"data":{"x":"synthetic"}}
        self.assertEqual(state_proof(secret,p)["uid"],"state")
        secret["data"]={}
        with self.assertRaises(RuntimeError):state_proof(secret,p)

def main():
    if "--selftest" in sys.argv:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(Contracts)
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() and result.testsRun==11 else 1)
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=["prepare","execute","commit"])
    parser.add_argument("--kubeconfig",required=True);parser.add_argument("--source",required=True)
    parser.add_argument("--expected-pod-uid");parser.add_argument("--journal")
    args=parser.parse_args();need(re.fullmatch("[a-f0-9]{40}",args.source),"source revision")
    op=Operator(args);getattr(op,args.action)()
if __name__=="__main__":main()

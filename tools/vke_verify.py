"""Source-bound, credential-free CS qualification on an existing approved CI node.

Owner-side only. Uses the common new-node bootstrap exclusive Lease; never
takes over an extant/expired holder. No node/PVC/provider purchase or authority
handoff. Runtime source, quotas, complete inventory and terminal outcomes are
read back. Evidence remains in retained Job logs until qualified cloud custody.
"""
import argparse, base64, datetime, hashlib, io, json, re, shlex, subprocess, tarfile, time, uuid, urllib.parse

REPO = "mithril-lang/mithril-cs"
NS = "mithril-cs-ci"
LNS = "mithril-ci-control"
LEASE = "mithril-newnode-bootstrap-exclusive-v1"
BB = "docker.io/babashka/babashka@sha256:f27dfcaf0b7e8e839c84b00c11377320abbd6aaaa81d187a74ebc470b9f66829"
GIB = 1024 ** 3

def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def complete(obj, kind):
    need(obj.get("kind") == kind + "List" and obj.get("metadata", {}).get("resourceVersion")
         and not obj["metadata"].get("continue"), "incomplete provider inventory")
    return obj["items"]

def terminal(pod):
    if (pod.get("metadata", {}).get("deletionTimestamp")
        or pod.get("status", {}).get("phase") not in ["Succeeded", "Failed"]
        or pod.get("spec", {}).get("ephemeralContainers")
        or pod.get("status", {}).get("ephemeralContainerStatuses")):
        return False
    for declaration, observation in [("containers", "containerStatuses"), ("initContainers", "initContainerStatuses")]:
        declared = pod.get("spec", {}).get(declaration, [])
        observed = pod.get("status", {}).get(observation, [])
        names = [c.get("name") for c in declared]
        seen = [c.get("name") for c in observed]
        if declaration == "containers" and not names: return False
        if len(set(names)) != len(names) or len(set(seen)) != len(seen) or set(names) != set(seen): return False
        for status in observed:
            state = status.get("state", {})
            if (set(state) != {"terminated"} or type(state["terminated"].get("exitCode")) is not int
                or type(status.get("restartCount")) is not int):
                return False
    return True

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--kubeconfig", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--node", required=True)
    p.add_argument("--node-uid", required=True)
    p.add_argument("--baseline", required=True, help="existing owner-reviewed CI platform policy JSON")
    p.add_argument("--additional-slot", action="store_true", help="Preserve exact legacy unknown reservation (4GiB/2CPU); add bounded CS slot")
    args = p.parse_args()
    need(re.fullmatch("[0-9a-f]{40}", args.source), "source revision required")
    k = ["kubectl", "--kubeconfig", args.kubeconfig, "--request-timeout=12s"]
    def kube(method, *arguments, body=None, absent=False):
        command = k + [method] + list(arguments)
        if absent: command += ["--ignore-not-found=true"]
        r = subprocess.run(command, input=json.dumps(body) if body is not None else None,
                           capture_output=True, text=True, timeout=20)
        need(r.returncode == 0, "provider operation failed; reconcile before retry")
        return json.loads(r.stdout) if r.stdout.strip() else None
    def get(kind, *rest, absent=False):
        if kind in ["pods", "jobs", "nodes"]:
            prefix = "/apis/batch/v1" if kind == "jobs" else "/api/v1"
            if "-n" in rest: prefix += "/namespaces/" + rest[rest.index("-n")+1]
            query = {"limit":"2000"}
            if "-l" in rest: query["labelSelector"] = rest[rest.index("-l")+1]
            return kube("get", "--raw", prefix+"/"+kind+"?"+urllib.parse.urlencode(query))
        return kube("get", kind, *rest, "-o", "json", absent=absent)
    def create(obj):
        # Every operation is single-attempt; a timeout terminates with journal held.
        r = kube("create", "-f", "-", "-o", "json", body=obj)
        need(r["metadata"]["name"] == obj["metadata"]["name"], "create identity mismatch")
        actual = get(obj["kind"], obj["metadata"]["name"], "-n", obj["metadata"].get("namespace", NS))
        need(actual["metadata"]["uid"] == r["metadata"]["uid"], "create readback mismatch")
        return actual
    def gh(path):
        r = subprocess.run(["gh", "api", "repos/" + REPO + "/" + path],
                           capture_output=True, text=True, timeout=30)
        need(r.returncode == 0, "source acquisition failed")
        return json.loads(r.stdout)
    commit = gh("git/commits/" + args.source)
    need(commit["sha"] == args.source, "commit identity")
    tree = gh("git/trees/" + commit["tree"]["sha"] + "?recursive=1")
    need(not tree.get("truncated"), "source tree truncated")
    expected = {}
    for row in tree["tree"]:
        if row["type"] == "tree": continue
        need(row["mode"] == "100644" and row["type"] == "blob"
             and re.fullmatch("[A-Za-z0-9_./-]+", row["path"])
             and ".." not in row["path"].split("/"), "unsupported source entry")
        expected[row["path"]] = row["sha"]
    acquired = subprocess.run(["gh","api","repos/"+REPO+"/tarball/"+args.source],
                              capture_output=True, timeout=45)
    need(acquired.returncode == 0 and len(acquired.stdout) <= 2*1024*1024, "source archive acquisition")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(acquired.stdout), mode="r:gz") as archive:
        count = 0
        for member in archive:
            count += 1
            need(count <= 256, "source archive entry budget")
            if member.isdir(): continue
            path = member.name.split("/",1)[-1]
            need(member.isfile() and path in expected and path not in files
                 and member.size <= 512*1024, "source archive entry")
            raw = archive.extractfile(member).read(512*1024+1)
            need(hashlib.sha1(b"blob "+str(len(raw)).encode()+bytes([0])+raw).hexdigest() == expected[path],
                 "source blob mismatch")
            files[path] = raw.decode("utf-8")
    need(set(files) == set(expected), "incomplete source archive")
    need(len(files) <= 64 and sum(len(v.encode()) for v in files.values()) <= 512 * 1024, "source budget")
    policy = json.load(open(args.baseline))
    old_rows = policy["platform_pods"]
    # Refresh identities only after original platform owner/image comparison.
    need(old_rows, "missing owner platform baseline")
    old_images = {tuple(sorted(s["imageID"] for s in row["status"]["containerStatuses"])) for row in old_rows}
    nodes = complete(get("nodes"), "Node")
    roster = {n["metadata"]["name"]: n["metadata"]["uid"] for n in nodes}
    need(roster.get(args.node) == args.node_uid, "node identity changed")
    node = next(n for n in nodes if n["metadata"]["name"] == args.node)
    platform = {}
    legacy_uid = "ac94ce8f-c3b7-4b53-b538-11bfa04600cb"
    legacy_job_uid = "e027dce0-eb67-4880-8f8f-c3d37ff80f93"
    def reserved_legacy(pod):
        if not args.additional_slot or pod["metadata"]["uid"] != legacy_uid: return False
        need(args.node_uid == "86f1c2a3-01f6-4ba9-92c0-9da0c4f3b21f"
             and pod["metadata"]["namespace"] == "mithril-ci-bounded"
             and digest(pod["spec"]) == "fb2d570a949105a8b0dd5459904ff466bbafe6958115b238365b0199754491f6"
             and pod.get("status",{}).get("phase") == "Failed"
             and not pod["metadata"].get("deletionTimestamp")
             and any(o.get("uid") == legacy_job_uid and o.get("controller") is True for o in pod["metadata"].get("ownerReferences",[])),
             "legacy reservation changed; owner reconciliation required")
        return True
    pods = complete(get("pods", "-A"), "Pod")
    for pod in pods:
        if pod["spec"].get("nodeName") != args.node or terminal(pod): continue
        if reserved_legacy(pod): continue  # Remains UNKNOWN and reserves 4GiB/2CPU, never reclassified as terminal.
        need(pod["metadata"]["namespace"] == "kube-system", "CI node has non-platform workload")
        need(pod.get("status", {}).get("phase") == "Running" and
             all(s.get("ready") for s in pod["status"].get("containerStatuses", [])), "platform not ready")
        owners = pod["metadata"].get("ownerReferences", [])
        need(len(owners) == 1 and owners[0]["kind"] in ["DaemonSet", "ReplicaSet"], "platform controller")
        images = sorted(s["imageID"] for s in pod["status"]["containerStatuses"])
        need(tuple(images) in old_images, "platform image changed")
        platform[pod["metadata"]["uid"]] = (digest(pod["spec"]), images)
    need(len(platform) >= 4, "platform baseline incomplete")
    # Source-only and synthetic tests. No worker token, model key, host mount or PVC.
    operation = uuid.uuid4().hex
    name = "mcs-" + args.source[:10] + "-" + operation[:6]
    cmname = name + "-source"
    own = None
    lease_uid = None
    def fresh():
        current_nodes = complete(get("nodes"), "Node")
        need({n["metadata"]["name"]: n["metadata"]["uid"] for n in current_nodes} == roster, "node roster changed")
        for n in current_nodes:
            c = {x["type"]: x["status"] for x in n["status"]["conditions"]}
            need(c.get("Ready") == "True" and all(c.get(t) == "False" for t in
                 ["MemoryPressure", "DiskPressure", "PIDPressure"]), "node health hold")
        ps = complete(get("pods", "-A"), "Pod")
        js = complete(get("jobs", "-A"), "Job")
        seen = set()
        reserved_seen = False
        for pod in ps:
            spec = pod["spec"]
            if spec.get("nodeName") and spec["nodeName"] != args.node: continue
            if not spec.get("nodeName") and any(node["metadata"]["labels"].get(x) != v for x, v in spec.get("nodeSelector", {}).items()): continue
            if reserved_legacy(pod):
                reserved_seen = True
                continue
            if terminal(pod): continue
            uid = pod["metadata"]["uid"]
            if uid in platform:
                need((digest(spec), sorted(s["imageID"] for s in pod["status"]["containerStatuses"])) == platform[uid], "platform drift")
                need(all(s.get("ready") for s in pod["status"]["containerStatuses"]), "platform readiness")
                seen.add(uid); continue
            need(own is not None and any(o.get("uid") == own for o in pod["metadata"].get("ownerReferences", [])), "concurrent workload hold")
        need(seen == set(platform), "platform disappeared")
        if args.additional_slot: need(reserved_seen, "legacy reservation missing; requalify instead of clearing hold")
        for job in js:
            if args.additional_slot and job["metadata"]["uid"] == legacy_job_uid:
                need(digest(job["spec"]) == "020378a25cdb70b41b659a41bf4afad4c9154c3721df0cd4495a90e8418bb4c0"
                     and not job.get("status",{}).get("active") and not job.get("status",{}).get("terminating")
                     and any(c.get("type") == "Failed" and c.get("status") == "True" for c in job.get("status",{}).get("conditions",[])),
                     "legacy source/authority changed")
            spec = job["spec"]["template"]["spec"]
            if spec.get("nodeName") and spec["nodeName"] != args.node: continue
            if any(node["metadata"]["labels"].get(x) != v for x, v in spec.get("nodeSelector", {}).items()): continue
            done = any(c.get("type") in ["Complete", "Failed"] and c.get("status") == "True" for c in job.get("status", {}).get("conditions", []))
            need((done and not job["metadata"].get("deletionTimestamp") and not job.get("status", {}).get("active") and not job.get("status", {}).get("terminating")) or job["metadata"]["uid"] == own, "concurrent Job hold")
        s = kube("get", "--raw", "/api/v1/nodes/" + args.node + "/proxy/stats/summary")["node"]
        for key in ["cpu", "memory", "fs"]:
            age = time.time() - datetime.datetime.fromisoformat(s[key]["time"].replace("Z", "+00:00")).timestamp()
            need(-5 <= age <= 30, "stale metrics")
        need(s["memory"]["availableBytes"] >= (5.5 if args.additional_slot else 5) * GIB and s["fs"]["availableBytes"] >= 48 * GIB, "headroom hold")
        need(s["cpu"]["usageNanoCores"] <= (1500000000 if own else 500000000), "CPU hold")
        if lease_uid:
            lease = get("lease", LEASE, "-n", LNS)
            need(lease["metadata"]["uid"] == lease_uid and lease["spec"]["holderIdentity"] == operation, "lease lost")
        return {"memory_available": s["memory"]["availableBytes"], "cpu_nanocores": s["cpu"]["usageNanoCores"]}
    initial = fresh()
    need(get("lease", LEASE, "-n", LNS, absent=True) is None, "common slot occupied; no takeover")
    # Dedicated quota addition is within Jun's explicit slot-increase authority.
    ns = get("namespace", NS, absent=True)
    if ns is None:
        r = subprocess.run(k + ["create", "-f", "-", "-o", "json"], input=json.dumps({
          "apiVersion":"v1","kind":"Namespace","metadata":{"name":NS,"labels":{"pod-security.kubernetes.io/enforce":"restricted","mithril.fund/owner":"MITHRIL-2471"}}}),
          capture_output=True,text=True,timeout=20)
        need(r.returncode == 0, "namespace creation unknown")
    for obj in [
        {"apiVersion":"v1","kind":"ResourceQuota","metadata":{"name":"cs-qualification","namespace":NS},"spec":{"hard":{"pods":"1","limits.cpu":"1","requests.cpu":"1","limits.memory":"1536Mi","requests.memory":"1536Mi","limits.ephemeral-storage":"2Gi","requests.ephemeral-storage":"2Gi","persistentvolumeclaims":"0","services.loadbalancers":"0","services.nodeports":"0"}}},
        {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"deny-all","namespace":NS},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}}]:
        existing = get(obj["kind"], obj["metadata"]["name"], "-n", NS, absent=True)
        if existing is None: create(obj)
        else: need(existing["spec"] == obj["spec"], "existing lane config mismatch")
    priority_name = "mithril-cs-2471-nonpreemptible"
    priority = get("priorityclass", priority_name, absent=True)
    if priority is None:
        obj = {"apiVersion":"scheduling.k8s.io/v1","kind":"PriorityClass",
               "metadata":{"name":priority_name,"labels":{"mithril.fund/owner":"MITHRIL-2471"}},
               "value":-10,"globalDefault":False,"preemptionPolicy":"Never",
               "description":"Bounded low-priority CS qualification; never preempts existing work"}
        priority = kube("create","-f","-","-o","json",body=obj)
    need(priority.get("value")==-10 and priority.get("globalDefault", False) is False
         and priority.get("preemptionPolicy")=="Never", "priority class drift")
    ledger = {"operation":operation,"source":args.source,"phase":"pre-submit","job":name,"image":BB,"initial":initial,"legacy_reservation":{"outcome":"UNKNOWN","memory_bytes":4*GIB,"cpu":2,"pod_uid":legacy_uid} if args.additional_slot else None}
    journal = {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":name+"-journal","namespace":NS},"data":{"state":json.dumps(ledger)}}
    create(journal)
    lease = create({"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"name":LEASE,"namespace":LNS,"annotations":{"mithril.fund/owner_issue":"MITHRIL-2471","mithril.fund/source":args.source}},"spec":{"holderIdentity":operation,"leaseDurationSeconds":900,"acquireTime":datetime.datetime.now(datetime.timezone.utc).isoformat()}})
    lease_uid = lease["metadata"]["uid"]
    fresh()
    data = {"f"+str(i):content for i,content in enumerate(files.values())}
    manifest = {path:hashlib.sha256(value.encode()).hexdigest() for path,value in files.items()}
    data["manifest.json"] = json.dumps(manifest)
    cm = create({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":cmname,"namespace":NS},"immutable":True,"data":data})
    need(cm["data"] == data and cm.get("immutable") is True, "source ConfigMap changed")
    script = "set -eu\nmkdir -p /tmp/source\n"
    for i,path in enumerate(files):
        script += "mkdir -p " + shlex.quote("/tmp/source/"+path.rsplit("/",1)[0] if "/" in path else "/tmp/source") + "\n"
        script += "cp /input/f"+str(i)+" "+shlex.quote("/tmp/source/"+path)+"\n"
    script += r"""
cd /tmp/source
/init/tini --version
bb --version
bb test
bb cs review test/fixtures/demo --authorized
bb cs pentest-fixture --authorized
i=0; while [ "$i" -lt 200 ]; do sh -c 'sleep 0.02 &' ; i=$((i+1)); done
sleep 2
bb -e '(let [states (keep (fn [p] (try (second (re-find #"^\d+ \(.*\) ([A-Z])" (slurp (str p "/stat")))) (catch Exception _ nil))) (filter #(.isDirectory %) (.listFiles (java.io.File. "/proc")))) zombies (count (filter #{"Z"} states))] (assert (zero? zombies)) (prn {:tini-reaping :passed :zombies zombies}))'
if /init/tini -s -- sh -c 'exit 42'; then exit 1; else [ "$?" = 42 ]; fi
/init/tini -s -g -- sh -c 'trap "exit 0" TERM; sleep 30 & wait' &
child=$!; sleep 0.2; kill -TERM "$child"; wait "$child"
echo TINI_FIXTURE_PASS
"""

    container = {"name":"contracts","image":BB,"command":["/init/tini","-g","--","sh","-c",script],"env":[{"name":"HOME","value":"/tmp"},{"name":"TMPDIR","value":"/tmp"}],
      "resources":{"requests":{"cpu":"200m","memory":"256Mi","ephemeral-storage":"256Mi"},"limits":{"cpu":"500m","memory":"512Mi","ephemeral-storage":"512Mi"}},
      "securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}},
      "volumeMounts":[{"name":"init","mountPath":"/init","readOnly":True},{"name":"source","mountPath":"/input","readOnly":True},{"name":"scratch","mountPath":"/tmp"}]}
    spec = {"restartPolicy":"Never","priorityClassName":priority_name,"preemptionPolicy":"Never","automountServiceAccountToken":False,"enableServiceLinks":False,
      "nodeSelector":{"kubernetes.io/hostname":args.node},"tolerations":[{"key":"mithril.fund/execution-lane","value":"ci-profile","operator":"Equal","effect":"NoSchedule"}],
      "securityContext":{"runAsNonRoot":True,"runAsUser":1000,"runAsGroup":1000,"fsGroup":1000,"seccompProfile":{"type":"RuntimeDefault"}},
      "containers":[container],"volumes":[{"name":"init","configMap":{"name":"router-init-tini-c5b0666b4cb6","defaultMode":365}},{"name":"source","configMap":{"name":cmname}},{"name":"scratch","emptyDir":{"sizeLimit":"512Mi"}}]}
    job = {"apiVersion":"batch/v1","kind":"Job","metadata":{"name":name,"namespace":NS,"annotations":{"mithril.fund/source":args.source}},
      "spec":{"backoffLimit":0,"activeDeadlineSeconds":240,"template":{"metadata":{"labels":{"mithril.fund/cs-run":name}},"spec":spec}}}
    actual = create(job)
    own = actual["metadata"]["uid"]
    ledger.update(phase="submitted",job_uid=own,source_cm_uid=cm["metadata"]["uid"],lease_uid=lease_uid)
    print(json.dumps(ledger),flush=True)
    deadline = time.monotonic()+260
    while time.monotonic()<deadline:
        fresh()
        j = get("job",name,"-n",NS)
        need(j["metadata"]["uid"] == own, "Job replaced")
        ps = complete(get("pods","-n",NS,"-l","job-name="+name),"Pod")
        need(len(ps)<=1, "unexpected retries")
        conditions = j.get("status",{}).get("conditions",[])
        if any(c.get("type") in ["Complete","Failed"] and c.get("status")=="True" for c in conditions) and ps and terminal(ps[0]):
            pod=ps[0]
            need(any(o.get("uid")==own for o in pod["metadata"].get("ownerReferences",[])), "Pod owner mismatch")
            statuses=pod["status"]["containerStatuses"]
            need(len(statuses)==1 and statuses[0]["imageID"].split("@")[-1]==BB.split("@")[-1], "runtime image mismatch")
            logs=subprocess.run(k+["logs",pod["metadata"]["name"],"-n",NS,"--limit-bytes=65536"],capture_output=True,text=True,timeout=20)
            need(logs.returncode==0, "logs unavailable; keep lease")
            success=any(c.get("type")=="Complete" and c.get("status")=="True" for c in conditions) and all(s.get("restartCount")==0 and s["state"]["terminated"]["exitCode"]==0 for s in statuses)
            ledger.update(phase="terminal",success=success,pod_uid=pod["metadata"]["uid"],log_sha256=hashlib.sha256(logs.stdout.encode()).hexdigest(),
                          image=BB,source_tree=commit["tree"]["sha"],source_manifest_sha256=digest(manifest))
            # Bounded logs remain in the retained Pod. Only metadata enters journal.
            old=get("ConfigMap",name+"-journal","-n",NS)
            old["data"]["state"]=json.dumps(ledger)
            kube("replace","-f","-","-o","json",body=old)
            current=get("lease",LEASE,"-n",LNS)
            need(current["metadata"]["uid"]==lease_uid and current["spec"]["holderIdentity"]==operation, "release owner changed")
            kube("delete","--raw","/apis/coordination.k8s.io/v1/namespaces/"+LNS+"/leases/"+LEASE,"-f","-",body={"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":lease_uid,"resourceVersion":current["metadata"]["resourceVersion"]}})
            need(get("lease",LEASE,"-n",LNS,absent=True) is None, "release unknown")
            print(json.dumps(ledger),flush=True)
            print(logs.stdout,flush=True)
            raise SystemExit(0 if success else 1)
        time.sleep(3)
    raise RuntimeError("deadline unknown; retain source/journal/lease for reconciliation")
if __name__=="__main__":main()

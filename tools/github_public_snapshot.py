"""Trusted owner-side public source acquisition; never executes target code.

The caller publishes the bounded output into the dedicated private R2 fixed
github-public-snapshots prefix after a hash read-back. GitHub credentials remain
inside the existing gh owner client, never in the output or analysis Worker.
"""
import argparse, hashlib, json, os, pathlib, subprocess, time

def acquire(repository, number):
    if repository != "mithril-lang/mithril-cs" or not 1 <= number <= 1000000:
        raise ValueError("company public repository scope required")
    def get(path):
        result=subprocess.run(["gh","api",path],capture_output=True,timeout=20)
        if result.returncode or len(result.stdout)>1048576:
            raise ValueError("GitHub source read failed or exceeded bound")
        return json.loads(result.stdout)
    info=get("repos/"+repository)
    if info.get("visibility")!="public" or info.get("full_name")!=repository:
        raise ValueError("public repository identity changed")
    endpoint="repos/"+repository+"/pulls/"+str(number)
    first=get(endpoint); files=get(endpoint+"/files?per_page=100"); second=get(endpoint)
    if first["head"]["sha"]!=second["head"]["sha"] or first["base"]["sha"]!=second["base"]["sha"] or first["changed_files"]!=second["changed_files"]:
        raise ValueError("PR source changed")
    if first["base"]["repo"]["full_name"]!=repository or not isinstance(files,list) or len(files)>100:
        raise ValueError("source boundary changed")
    pr={"title":first["title"],"changed_files":first["changed_files"],
        "head":{"sha":first["head"]["sha"]},"base":{"sha":first["base"]["sha"],"repo":{"full_name":repository}}}
    selected=[{k:f[k] for k in ["filename","status","additions","deletions","patch"] if k in f} for f in files]
    return {"schemaVersion":1,"public":True,"repository":repository,"number":number,
            "head":pr["head"]["sha"],"base":pr["base"]["sha"],"observedAt":int(time.time()*1000),"pr":pr,"files":selected}

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--repository",default="mithril-lang/mithril-cs")
    parser.add_argument("--pull",type=int,required=True);parser.add_argument("--output",type=pathlib.Path,required=True)
    args=parser.parse_args();destination=args.output.resolve()
    if not args.output.is_absolute() or destination.is_relative_to(pathlib.Path(__file__).resolve().parent.parent):
        raise ValueError("private staging outside source repository required")
    value=acquire(args.repository,args.pull);raw=json.dumps(value,separators=(",",":"),ensure_ascii=False).encode()
    if len(raw)>1048576:raise ValueError("snapshot byte bound")
    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as file:file.write(raw)
    print(json.dumps({"repository":args.repository,"pull":args.pull,"head":value["head"],"observedAt":value["observedAt"],"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}))

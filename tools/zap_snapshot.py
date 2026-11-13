"""Pinned source transport for MITHRIL-2485; controller only, no worker credentials."""
import base64, concurrent.futures, gzip, hashlib, io, json, re, subprocess, tarfile
PINS = {
 "scanner": ("cloud-itonami/app-itonami-zap-proxy", "8bc8a410ad6836c55dedd5cf6ec3edea9e1f0b57"),
 "engine": ("kotoba-lang/org-babashka-nbb", "1675e6aab65d5a99e37840cc5012bc2eca6f4a07"),
 "stdlib": ("kotoba-lang/kotoba", "4bf68e1a1b205674c70f386d59e430801fae3572")}
def sha(b): return hashlib.sha256(b).hexdigest()
def api(path):
 p=subprocess.run(["gh","api","repos/"+path],capture_output=True,timeout=45)
 if p.returncode: raise RuntimeError("pinned source acquisition failed")
 return json.loads(p.stdout)
def acquire():
 files={}; provenance={}; roots=set()
 for group,(repo,rev) in PINS.items():
  c=api(repo+"/git/commits/"+rev)
  if c["sha"]!=rev: raise RuntimeError("commit mismatch")
  t=api(repo+"/git/trees/"+c["tree"]["sha"]+"?recursive=1")
  if t.get("truncated"): raise RuntimeError("truncated source")
  rows={x["path"]:x for x in t["tree"] if x["type"]=="blob"}
  def read(path):
   x=rows[path]
   if x["mode"] not in ["100644","100755"] or x.get("size",0)>2*1024*1024: raise RuntimeError("source mode/size")
   b=base64.b64decode(api(repo+"/git/blobs/"+x["sha"])["content"])
   if hashlib.sha1(b"blob "+str(len(b)).encode()+bytes([0])+b).hexdigest()!=x["sha"]: raise RuntimeError("Git blob mismatch")
   return b
  if group=="scanner":
   selected=[p for p in rows if p.startswith(("src/","test/","resources/","plugin/","kotoba/src/")) or p in
             ["scripts/coverage-gate.sh","scripts/check-cwe-matrix.py","deps.edn","nbb.edn","LICENSE"]]
  elif group=="engine":
   selected=[p for p in rows if p.startswith(("lib/","node_modules/import-meta-resolve/")) or p in ["cli.js","index.mjs","package.json","LICENSE"]]
  else:
   pending=["kotoba.bytes","kotoba.test","kotoba.edn","kotoba.text","kotoba.fs"]
   while pending:
    root=pending.pop()
    if root in roots: continue
    roots.add(root)
    if len(roots)>32: raise RuntimeError("stdlib dependency budget")
    dep="lib/"+root+"/deps.edn"; raw=read(dep); files[group+"/"+dep]=raw
    pending.extend(re.findall(r':local/root\s+"\.\./([A-Za-z0-9._-]+)"',raw.decode()))
   selected=[p for p in rows if any(p.startswith("lib/"+r+"/src/") for r in roots) or p in ["LICENSE"]]
  if len(selected)>600: raise RuntimeError("snapshot file budget")
  with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
   for path,raw in zip(selected,pool.map(read,selected)):
    if not re.fullmatch(r"[A-Za-z0-9_./-]+",path) or ".." in path.split("/"): raise RuntimeError("source path")
    files[group+"/"+path]=raw
  provenance[group]={"repository":repo,"revision":rev,"tree":c["tree"]["sha"]}
 if len(files)>1000 or sum(map(len,files.values()))>12*1024*1024: raise RuntimeError("snapshot byte budget")
 manifest={"pins":provenance,"stdlib_roots":sorted(roots),"files":{p:{"sha256":sha(b),"bytes":len(b)} for p,b in files.items()}}
 files["manifest.json"]=json.dumps(manifest,sort_keys=True).encode()
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode="w") as tar:
  for path,b in sorted(files.items()):
   info=tarfile.TarInfo(path);info.size=len(b);info.mode=0o644;info.mtime=0
   tar.addfile(info,io.BytesIO(b))
 packed=gzip.compress(out.getvalue(),mtime=0)
 if len(packed)>4*1024*1024: raise RuntimeError("packed snapshot budget")
 return packed,manifest
def unpack(parts,destination):
 from pathlib import Path
 raw=b"".join(Path(p).read_bytes() for p in parts)
 if len(raw)>4*1024*1024: raise RuntimeError("packed snapshot budget")
 files={}
 with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tar:
  for m in tar:
   if (not m.isfile() or not re.fullmatch(r"[A-Za-z0-9_./-]+",m.name)
       or ".." in m.name.split("/") or m.name.startswith("/") or m.name in files
       or m.size>2*1024*1024 or len(files)>=1000): raise RuntimeError("unsafe snapshot")
   files[m.name]=tar.extractfile(m).read()
   if sum(map(len,files.values()))>12*1024*1024: raise RuntimeError("unpacked budget")
 manifest=json.loads(files.pop("manifest.json"))
 if {g:(p["repository"],p["revision"]) for g,p in manifest["pins"].items()}!=PINS: raise RuntimeError("runtime pins mismatch")
 if set(files)!=set(manifest["files"]): raise RuntimeError("incomplete runtime")
 for path,b in files.items():
  if {"sha256":sha(b),"bytes":len(b)}!=manifest["files"][path]: raise RuntimeError("snapshot hash")
 for path,b in files.items():
  p=Path(destination)/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 (Path(destination)/"manifest.json").write_text(json.dumps(manifest,sort_keys=True))
 return manifest
if __name__=="__main__":
 import sys
 unpack(sys.argv[2:],sys.argv[1])

import engine from "./engine.mjs";
import {fonts} from "./fonts.mjs";
import {page, css, client, logo, sitemap} from "./ui.mjs";
import {social} from "./branding.mjs";
import {reviewPullRequest,snapshotReader} from "./github.mjs";
const ORIGIN="https://cs.mithril.fund";
const UUID=/^[a-f0-9-]{36}$/i;
const SAFE_HEADERS=["content-type","content-length","strict-transport-security","x-content-type-options","content-security-policy","referrer-policy","x-frame-options"];
const json=(value,status=200)=>Response.json(value,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}});
class Failure extends Error {constructor(status,code){super(code);this.status=status;this.code=code;}}
const fail=(status,code)=>{throw new Failure(status,code)};
const bytes=x=>new TextEncoder().encode(x);
const hex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,"0")).join("");
export const sha=async x=>hex(await crypto.subtle.digest("SHA-256",typeof x==="string"?bytes(x):x));
export async function bounded(response,limit){
 if(!response.body)return new Uint8Array();
 const reader=response.body.getReader();let n=0,parts=[];
 try {while(true){const {value,done}=await reader.read();if(done)break;n+=value.length;if(n>limit)fail(413,"response_limit");parts.push(value);}}
 finally {await reader.cancel().catch(()=>{});}
 const result=new Uint8Array(n);let p=0;for(const v of parts){result.set(v,p);p+=v.length;}return result;
}
const data=async r=>JSON.parse(new TextDecoder().decode(await bounded(r,262144)));
export function normalizeTarget(raw){
 if(typeof raw!=="string"||raw.length>2048)fail(400,"invalid_target");
 let u;try{u=new URL(raw);}catch{fail(400,"invalid_target");}
 if(u.protocol!=="https:"||u.username||u.password||u.port||u.search||u.hash||u.pathname!=="/"||
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(u.hostname))fail(400,"https_root_required");
 return u.origin+"/";
}
export function sessionCookie(request){
 const values=(request.headers.get("cookie")||"").split(";").map(x=>x.trim()).filter(x=>x.startsWith("mf_session="));
 if(values.length!==1)return null;
 const token=values[0].slice(11);return /^[A-Za-z0-9_-]{20,256}$/.test(token)?token:null;
}
async function csrfKey(token){return crypto.subtle.importKey("raw",bytes(token),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);}
async function identity(request,env){
 const token=sessionCookie(request);if(!token)fail(401,"sign_in_required");
 const r=await env.AUTH.fetch(new Request("https://auth.mithril.fund/v1/session",{headers:{cookie:"mf_session="+token},redirect:"manual",signal:AbortSignal.timeout(8000)}));
 if(r.status===401)fail(401,"sign_in_required");
 if(!r.ok)fail(503,"identity_unavailable");
 const p=await data(r);if(typeof p.userId!=="string"||!p.userId||p.userId.length>128)fail(503,"identity_unavailable");
 const key=await csrfKey(token);
 return {id:p.userId,token,key,csrf:hex(await crypto.subtle.sign("HMAC",key,bytes(ORIGIN)))};
}
async function writeGuard(req,actor){
 if(req.headers.get("origin")!==ORIGIN||["cross-site","same-site"].includes(req.headers.get("sec-fetch-site")))fail(403,"origin_denied");
 const supplied=req.headers.get("x-csrf-token")||"";
 if(!/^[a-f0-9]{64}$/.test(supplied)||!await crypto.subtle.verify("HMAC",actor.key,Uint8Array.from(supplied.match(/../g),x=>parseInt(x,16)),bytes(ORIGIN)))fail(403,"csrf_denied");
 if(!req.headers.get("content-type")?.startsWith("application/json"))fail(415,"json_required");
}
async function projectAccess(req,env,actor,project){
 if(project==="personal")return;
 if(!/^[a-zA-Z0-9_-]{1,100}$/.test(project))fail(400,"invalid_project");
 let after="";
 for(let i=0;i<5;i++){
  const r=await env.WORKSPACE.fetch(new Request("https://api.mithril.fund/v1/workspace/repository/project?limit=100&after="+encodeURIComponent(after),{headers:{cookie:"mf_session="+actor.token},redirect:"manual",signal:AbortSignal.timeout(8000)}));
  if(r.status===401)fail(401,"sign_in_required");if(!r.ok)fail(503,"project_authority_unavailable");
  const v=await data(r);if(v.userId!==actor.id||!Array.isArray(v.documents))fail(503,"project_authority_unavailable");
  if(v.documents.some(d=>d.id===project&&!d.deleted))return;
  if(!v.nextAfter)break;after=v.nextAfter;
 }
 fail(403,"project_denied");
}
const stmt=(env,sql,...args)=>env.DB.prepare(sql).bind(...args);
const rows=async(env,sql,...args)=>(await stmt(env,sql,...args).all()).results;
const first=(env,sql,...args)=>stmt(env,sql,...args).first();
const audit=(env,a,p,action,id)=>stmt(env,"INSERT INTO cs_audit VALUES(?,?,?,?,?,?)",crypto.randomUUID(),a,p,action,id,Date.now()).run();
async function target(env,a,p,id){
 const t=await first(env,"SELECT * FROM cs_targets WHERE id=? AND owner=? AND project=?",id,a,p);if(!t)fail(404,"target_not_found");return t;
}
const safeTarget=t=>({id:t.id,url:t.url,label:t.label,version:t.version,paused:!!t.paused,verifiedAt:t.verified_at,
 verification:{name:"_mithril-cs."+new URL(t.url).hostname,type:"TXT",value:"mithril-cs="+t.proof},createdAt:t.created_at});
function pilotHost(env,url){
 if(!(env.ALLOWED_HOSTS||"").split(",").includes(new URL(url).hostname))fail(409,"target_execution_not_enabled");
}
async function ownership(env,t){
 pilotHost(env,t.url);
 const u=new URL("https://cloudflare-dns.com/dns-query");u.searchParams.set("name","_mithril-cs."+new URL(t.url).hostname);u.searchParams.set("type","TXT");
 const r=await fetch(u,{headers:{accept:"application/dns-json"},redirect:"manual",signal:AbortSignal.timeout(5000)});
 if(!r.ok)fail(503,"ownership_lookup_failed");
 const v=await data(r);if(v.Status!==0||!Array.isArray(v.Answer)||!v.Answer.some(x=>x.type===16&&x.data.replace(/"/g,"")==="mithril-cs="+t.proof))fail(409,"ownership_not_verified");
}
async function publicAddresses(host){
 // These execution hosts are a separately configured, owner-approved allowlist.
 // Check current DNS too; no arbitrary customer origin or VPC/private binding.
 const lists=await Promise.all(["A","AAAA"].map(async type=>{
  const u=new URL("https://cloudflare-dns.com/dns-query");u.searchParams.set("name",host);u.searchParams.set("type",type);
  const r=await fetch(u,{headers:{accept:"application/dns-json"},redirect:"manual",signal:AbortSignal.timeout(5000)});
  if(!r.ok)fail(503,"dns_unavailable");const v=await data(r);if(v.Status!==0)fail(409,"dns_unavailable");
  return (v.Answer||[]).filter(x=>[1,28].includes(x.type)).map(x=>x.data);
 }));
 const addresses=lists.flat();if(!addresses.length)fail(409,"dns_unavailable");
 // Fail closed to known public Cloudflare ranges for the initial company pilot.
 for(const ip of addresses){
  if(ip.includes(":")){if(!/^(2606:4700:|2803:f800:|2400:cb00:|2a06:98c[0-7]:|2405:(?:8100|b500):)/i.test(ip))fail(409,"unqualified_destination");}
  else {const a=ip.split(".").map(Number);if(a.length!==4||a.some(x=>!Number.isInteger(x)||x<0||x>255)||
   !((a[0]===104&&a[1]>=16&&a[1]<=27)||(a[0]===172&&a[1]>=64&&a[1]<=71)||(a[0]===188&&a[1]===114&&(a[2]===96||a[2]===97))||(a[0]===162&&a[1]===159)))fail(409,"unqualified_destination");}
 }
 return addresses;
}
async function bodyObservation(response){
 const reader=response.body?.getReader();let total=0,complete=true,parts=[];
 if(reader)try{while(true){const {value,done}=await reader.read();if(done)break;
  const room=1048577-total,part=value.slice(0,Math.max(0,room));parts.push(part);total+=part.length;
  if(total>1048576){complete=false;break;}}}finally{await reader.cancel().catch(()=>{});}
 const out=new Uint8Array(total);let n=0;for(const p of parts){out.set(p,n);n+=p.length;}
 return {bytes:total,bodyComplete:complete,bodyPrefixSha256:await sha(out)};
}
async function currentGrant(env,req,actor,project,t,run){
 const again=await identity(req,env);if(again.id!==actor.id)fail(403,"actor_changed");
 await projectAccess(req,env,again,project);
 const now=await target(env,actor.id,project,t.id);
 if(now.paused||now.version!==t.version||!now.verified_at||Date.now()-now.verified_at>7*86400000)fail(409,"target_grant_changed");
 const active=await first(env,"SELECT status,expires_at FROM cs_runs WHERE id=? AND owner=? AND project=?",run,actor.id,project);
 if(active?.status!=="running")fail(409,"run_stopped");
 if(active.expires_at<=Date.now())fail(504,"run_deadline");
 return active;
}
async function execute(req,env,actor,project,t,id){
 const start=Date.now();
 try{
  const admitted=await stmt(env,"UPDATE cs_runs SET status='running',started_at=? WHERE id=? AND owner=? AND project=? AND status='queued'",start,id,actor.id,project).run();
  if(admitted.meta.changes!==1)return;
  await currentGrant(env,req,actor,project,t,id);await ownership(env,t);const addresses=await publicAddresses(new URL(t.url).hostname);
  const permit=await currentGrant(env,req,actor,project,t,id);
  const remaining=Math.min(15000,permit.expires_at-Date.now());if(remaining<=0)fail(504,"run_deadline");
  const response=await fetch(t.url,{method:"GET",redirect:"manual",headers:{"user-agent":"Mithril-CS/0.2 (+https://cs.mithril.fund; authorized passive review)","accept":"text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"},signal:AbortSignal.timeout(remaining),cf:{cacheTtl:0,cacheEverything:false}});
  const observation=await bodyObservation(response);
  if(Date.now()-start>engine.limits["run-deadline-ms"])fail(504,"run_deadline");
  const headers=Object.fromEntries(SAFE_HEADERS.filter(k=>response.headers.has(k)).map(k=>[k,response.headers.get(k)]));
  const result=engine.assess({url:t.url,status:response.status,headers,"body-complete":observation.bodyComplete});
  const report={schemaVersion:1,runId:id,source:env.SOURCE_SHA,engine:result.engine,target:t.url,
   targetVersion:t.version,startedAt:start,finishedAt:Date.now(),httpStatus:response.status,
   headersPresent:Object.keys(headers),headersSha256:await sha(JSON.stringify(headers)),...observation,
   addressSha256:await sha(JSON.stringify(addresses.sort())),...result};
  const raw=JSON.stringify(report),digest=await sha(raw),ownerHash=await sha(actor.id);
  const key="cs-runs/"+ownerHash+"/"+id+"/"+digest+".json";
  await env.EVIDENCE.put(key,raw,{httpMetadata:{contentType:"application/json"},customMetadata:{source:env.SOURCE_SHA,sha256:digest}});
  const stored=await env.EVIDENCE.get(key);if(!stored||await sha(await stored.arrayBuffer())!==digest)fail(503,"evidence_readback_failed");
  const indexKey="catalog-index/security/cs-runs/"+ownerHash+"/"+id+".json",indexRaw=JSON.stringify({schemaVersion:1,key,sha256:digest,source:env.SOURCE_SHA,runId:id,bytes:bytes(raw).length,access:"private",retention:"preserve until authorized custody review; no automatic expiry"});
  await env.EVIDENCE.put(indexKey,indexRaw,{httpMetadata:{contentType:"application/json"}});
  const indexRead=await env.EVIDENCE.get(indexKey);if(!indexRead||await sha(await indexRead.arrayBuffer())!==await sha(indexRaw))fail(503,"catalog_readback_failed");
  await currentGrant(env,req,actor,project,t,id);
  const batch=result.findings.map((finding,index)=>stmt(env,
   "INSERT INTO cs_findings(id,owner,project,run_id,target_id,rule_id,data,created_at) SELECT ?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM cs_runs r JOIN cs_targets t ON t.id=r.target_id WHERE r.id=? AND r.status='running' AND t.paused=0 AND t.version=r.target_version)",
   id+"-"+index,actor.id,project,id,t.id,finding["rule-id"],JSON.stringify(finding),Date.now(),id));
  batch.push(stmt(env,"UPDATE cs_runs SET status=?,report=?,evidence_key=?,evidence_sha256=?,finished_at=? WHERE id=? AND owner=? AND project=? AND status='running' AND EXISTS(SELECT 1 FROM cs_targets t WHERE t.id=target_id AND t.version=target_version AND t.paused=0)",
   response.status>=200&&response.status<300?"partial":"failed",raw,key,digest,Date.now(),id,actor.id,project));
  const saved=await env.DB.batch(batch);if(saved.at(-1).meta.changes!==1)fail(409,"run_commit_fenced");
 }catch(error){
  const code=error instanceof Failure?error.code:["TimeoutError","AbortError"].includes(error?.name)?"transport_timeout":"execution_failed";
  await stmt(env,"UPDATE cs_runs SET status=?,error=?,finished_at=? WHERE id=? AND owner=? AND project=? AND status IN ('queued','running')",
   ["actor_changed","target_grant_changed","sign_in_required","run_stopped","project_denied"].includes(code)?"cancelled":"failed",code,Date.now(),id,actor.id,project).run();
 }
}
export async function api(req,env,ctx){
 const url=new URL(req.url),path=url.pathname,method=req.method,actor=await identity(req,env);
 const project=url.searchParams.get("project")||"personal";await projectAccess(req,env,actor,project);
 const scope=await sha(JSON.stringify([actor.id,project,actor.csrf]));
 const reply=(v,status=200)=>{const r=json(v,status);r.headers.set("x-mithril-scope",scope);return r;};
 if(method==="GET"&&path==="/api/session")return reply({signedIn:true,csrf:actor.csrf,scope,project,source:env.SOURCE_SHA,
  capabilities:{mode:"single-url-passive",maxPages:1,allowedHosts:(env.ALLOWED_HOSTS||"").split(","),autoFix:"review-export-retest",githubPullRequests:false,organizationWorkspaces:false,
   publicReviewRepositories:(env.GITHUB_REPOSITORIES||"mithril-lang/mithril-cs").split(","),continuousScheduling:false}});
 if(method==="GET"&&path==="/api/reviews")return reply({reviews:(await rows(env,"SELECT id,repository,pull_number,head_sha,data,evidence_sha256,created_at FROM cs_reviews WHERE owner=? AND project=? ORDER BY created_at DESC LIMIT 30",actor.id,project)).map(r=>({...r,data:JSON.parse(r.data)}))});
 if(method==="GET"&&path==="/api/infrastructure")return reply({source:env.SOURCE_SHA,observedAt:Date.now(),kind:"configured-service-bindings",resources:[
  {id:"cs",kind:"Worker",name:"mithril-cs",available:true},
  {id:"auth",kind:"Service binding",name:"Mithril Auth",available:!!env.AUTH},
  {id:"workspace",kind:"Service binding",name:"Mithril Workspace",available:!!env.WORKSPACE},
  {id:"db",kind:"D1 binding",name:"CS application state",available:!!env.DB},
  {id:"evidence",kind:"R2 binding",name:"Private evidence",available:!!env.EVIDENCE}],
  edges:[["cs","auth"],["cs","workspace"],["cs","db"],["cs","evidence"]],
  coverage:{networkPolicy:"not-observed",cloudInventory:"not-connected",credentialsExposed:false}});
 if(method==="GET"&&path==="/api/targets")return reply({targets:(await rows(env,"SELECT * FROM cs_targets WHERE owner=? AND project=? ORDER BY created_at DESC LIMIT 100",actor.id,project)).map(safeTarget)});
 if(method==="GET"&&path==="/api/runs")return reply({runs:(await rows(env,"SELECT id,target_id,target_version,status,created_at,started_at,finished_at,expires_at,report,error,evidence_sha256 FROM cs_runs WHERE owner=? AND project=? ORDER BY created_at DESC LIMIT 100",actor.id,project)).map(r=>({...r,report:r.report?JSON.parse(r.report):null}))});
 if(method==="GET"&&path==="/api/findings")return reply({findings:(await rows(env,"SELECT * FROM cs_findings WHERE owner=? AND project=? ORDER BY created_at DESC LIMIT 200",actor.id,project)).map(r=>({...r,owner:undefined,data:JSON.parse(r.data)}))});
 if(method==="GET"&&path==="/api/fixes")return reply({fixes:(await rows(env,"SELECT * FROM cs_fixes WHERE owner=? AND project=? ORDER BY created_at DESC LIMIT 100",actor.id,project)).map(r=>({...r,owner:undefined}))});
 if(!["POST","PATCH"].includes(method))fail(405,"method_not_allowed");
 await writeGuard(req,actor);
 let body;try{body=JSON.parse(new TextDecoder().decode(await bounded(req,8192)));}catch(e){if(e instanceof Failure)throw e;fail(400,"invalid_json");}
 if(!body||typeof body!=="object"||Array.isArray(body))fail(400,"invalid_json");
 if(method==="POST"&&path==="/api/reviews"){
  if(body.authorized!==true)fail(400,"execution_acknowledgement_required");
  const count=await first(env,"SELECT COUNT(*) AS n FROM cs_reviews WHERE owner=? AND created_at>?",actor.id,Date.now()-86400000);
  if(count.n>=20)fail(429,"daily_run_limit");
  let report;
  const input={repository:body.repository,number:body.number,
   allowed:(env.GITHUB_REPOSITORIES||"mithril-lang/mithril-cs").split(","),reviewText:text=>engine.reviewText(text),sha,
   read:async endpoint=>{const r=await fetch(endpoint,{headers:{accept:"application/vnd.github+json","user-agent":"Mithril-CS","x-github-api-version":"2022-11-28"},redirect:"manual",signal:AbortSignal.timeout(8000)});
    if(!r.ok)throw new Error(r.status===403||r.status===429?"github_rate_limited":"github_unavailable");return data(r);}};
  try{report={...await reviewPullRequest(input),sourceFreshness:'upstream-reread',snapshotObservedAt:null};
  }catch(e){
   if(e.message==='github_rate_limited'&&input.allowed.includes(body.repository)&&/^mithril-lang\/[a-zA-Z0-9_.-]+$/.test(body.repository)&&Number.isSafeInteger(body.number)&&body.number>0&&body.number<=1000000){
    const object=await env.EVIDENCE.get('github-public-snapshots/'+body.repository+'/pull/'+body.number+'.json');
    if(object){try{if(!Number.isSafeInteger(object.size)||object.size>1048576)throw Error('github_snapshot_unavailable');
     const catalog=await env.EVIDENCE.get('catalog-index/security/github-public-snapshots/'+body.repository+'/pull/'+body.number+'.json');if(!catalog||!Number.isSafeInteger(catalog.size)||catalog.size>16384)throw Error('github_snapshot_unavailable');
     const raw=await object.arrayBuffer(),manifest=JSON.parse(new TextDecoder().decode(await catalog.arrayBuffer())),snapshot=JSON.parse(new TextDecoder().decode(raw));
     if(raw.byteLength!==manifest.bytes||await sha(raw)!==manifest.sha256||manifest.head!==snapshot.head||manifest.access!=='private')throw Error('github_snapshot_unavailable');
     report={...await reviewPullRequest({...input,read:snapshotReader(snapshot,{repository:body.repository,number:body.number,now:Date.now()})}),sourceFreshness:'owner-public-snapshot-current-head-unverified',snapshotObservedAt:snapshot.observedAt};
    }catch{fail(409,'github_snapshot_unavailable');}}
   }
   if(!report)fail(409,["repository_not_enabled","github_source_changed","github_source_invalid","github_patch_limit","github_rate_limited","github_unavailable"].includes(e.message)?e.message:"github_unavailable");
  }
  // Recheck the actual session/project after upstream I/O, before persistence.
  const again=await identity(req,env);if(again.id!==actor.id)fail(403,"actor_changed");await projectAccess(req,env,again,project);
  const old=await first(env,"SELECT id FROM cs_reviews WHERE owner=? AND project=? AND repository=? AND pull_number=? AND head_sha=?",actor.id,project,report.repository,report.number,report.head);if(old)return reply(old);
  const id=crypto.randomUUID(),raw=JSON.stringify({...report,source:env.SOURCE_SHA}),digest=await sha(raw),key="cs-reviews/"+await sha(actor.id)+"/"+id+"/"+digest+".json";
  await env.EVIDENCE.put(key,raw,{httpMetadata:{contentType:"application/json"}});const stored=await env.EVIDENCE.get(key);if(!stored||await sha(await stored.arrayBuffer())!==digest)fail(503,"evidence_readback_failed");
  const index="catalog-index/security/cs-reviews/"+await sha(actor.id)+"/"+id+".json",manifest=JSON.stringify({schemaVersion:1,key,sha256:digest,source:env.SOURCE_SHA,bytes:bytes(raw).length,access:"private",retention:"preserve until authorized custody review"});
  await env.EVIDENCE.put(index,manifest,{httpMetadata:{contentType:"application/json"}});const indexed=await env.EVIDENCE.get(index);if(!indexed||await sha(await indexed.arrayBuffer())!==await sha(manifest))fail(503,"catalog_readback_failed");
  await stmt(env,"INSERT INTO cs_reviews VALUES(?,?,?,?,?,?,?,?,?)",id,actor.id,project,report.repository,report.number,report.head,raw,digest,Date.now()).run();await audit(env,actor.id,project,"review.created",id);return reply({id,head:report.head,coverage:report.coverage},201);
 }
 if(method==="POST"&&path==="/api/logout"){
  const r=await env.AUTH.fetch(new Request("https://auth.mithril.fund/v1/logout",{method:"POST",headers:{cookie:"mf_session="+actor.token,origin:"https://auth.mithril.fund","content-type":"application/json"},body:"{}",redirect:"manual",signal:AbortSignal.timeout(8000)}));
  if(!r.ok)fail(503,"logout_pending");const h=new Headers({"cache-control":"no-store","content-type":"application/json","x-mithril-scope":scope});const c=r.headers.get("set-cookie");if(c)h.set("set-cookie",c);return new Response('{"ok":true}',{headers:h});
 }
 if(method==="POST"&&path==="/api/targets"){
  const normalized=normalizeTarget(body.url),label=typeof body.label==="string"?body.label.trim():"";
  if(!label||label.length>100||body.authorized!==true)fail(400,"scope_acknowledgement_required");
  const existing=await first(env,"SELECT * FROM cs_targets WHERE owner=? AND project=? AND url=?",actor.id,project,normalized);
  if(existing)return reply(safeTarget(existing));
  const count=await first(env,"SELECT COUNT(*) AS n FROM cs_targets WHERE owner=? AND project=?",actor.id,project);if(count.n>=20)fail(409,"target_limit");
  const id=crypto.randomUUID(),proof=crypto.randomUUID(),now=Date.now();
  await stmt(env,"INSERT INTO cs_targets(id,owner,project,url,label,proof,created_at) VALUES(?,?,?,?,?,?,?)",id,actor.id,project,normalized,label,proof,now).run();
  await audit(env,actor.id,project,"target.created",id);return reply(safeTarget(await target(env,actor.id,project,id)),201);
 }
 let match=path.match(/^\/api\/targets\/([a-f0-9-]{36})\/(verify|pause)$/i);
 if(match&&method==="POST"){
  const t=await target(env,actor.id,project,match[1]);
  if(match[2]==="verify"){await ownership(env,t);await publicAddresses(new URL(t.url).hostname);
   await stmt(env,"UPDATE cs_targets SET verified_at=?,version=version+1 WHERE id=? AND owner=? AND project=?",Date.now(),t.id,actor.id,project).run();
  }else {if(typeof body.paused!=="boolean")fail(400,"invalid_pause");
   await env.DB.batch([stmt(env,"UPDATE cs_targets SET paused=?,version=version+1 WHERE id=? AND owner=? AND project=?",body.paused?1:0,t.id,actor.id,project),
    stmt(env,"UPDATE cs_runs SET status='cancelled',error='target_paused',finished_at=? WHERE target_id=? AND owner=? AND project=? AND status IN ('queued','running')",Date.now(),t.id,actor.id,project)]);}
  await audit(env,actor.id,project,"target."+match[2],t.id);return reply(safeTarget(await target(env,actor.id,project,t.id)));
 }
 if(method==="POST"&&path==="/api/runs"){
  if(!UUID.test(body.operation||"")||body.authorized!==true)fail(400,"execution_acknowledgement_required");
  const t=await target(env,actor.id,project,body.targetId);pilotHost(env,t.url);
  if(t.paused||!t.verified_at||Date.now()-t.verified_at>7*86400000)fail(409,"target_not_ready");
  const old=await first(env,"SELECT id,status FROM cs_runs WHERE owner=? AND project=? AND operation=?",actor.id,project,body.operation);
  if(old){if((await first(env,"SELECT target_id FROM cs_runs WHERE id=?",old.id)).target_id!==t.id)fail(409,"operation_reused");return reply(old);}
  const count=await first(env,"SELECT COUNT(*) AS n FROM cs_runs WHERE owner=? AND created_at>?",actor.id,Date.now()-86400000);if(count.n>=20)fail(429,"daily_run_limit");
  const id=crypto.randomUUID(),now=Date.now();
  try{await stmt(env,"INSERT INTO cs_runs(id,owner,project,target_id,target_version,operation,status,created_at,expires_at) VALUES(?,?,?,?,?,?,'queued',?,?)",id,actor.id,project,t.id,t.version,body.operation,now,now+engine.limits["run-deadline-ms"]).run();}
  catch{fail(409,"run_already_active");}
  await audit(env,actor.id,project,"run.requested",id);
  ctx.waitUntil(execute(req,env,actor,project,t,id));return reply({id,status:"queued"},202);
 }
 match=path.match(/^\/api\/runs\/([a-f0-9-]{36})\/(cancel|reconcile)$/i);
 if(match&&method==="POST"){
  const r=await first(env,"SELECT * FROM cs_runs WHERE id=? AND owner=? AND project=?",match[1],actor.id,project);if(!r)fail(404,"run_not_found");
  if(match[2]==="reconcile"&&r.expires_at>Date.now())fail(409,"run_not_expired");
  await stmt(env,"UPDATE cs_runs SET status=?,error=?,finished_at=? WHERE id=? AND owner=? AND project=? AND status IN ('queued','running')",
   match[2]==="cancel"?"cancelled":"unknown",match[2]==="cancel"?"user_cancelled":"worker_outcome_unknown",Date.now(),r.id,actor.id,project).run();
  await audit(env,actor.id,project,"run."+match[2],r.id);return reply({ok:true});
 }
 match=path.match(/^\/api\/findings\/([a-f0-9-]{36}-[0-9]+)\/triage$/i);
 if(match&&method==="POST"){
  if(!["acknowledged","dismissed","needs-review"].includes(body.status)||typeof body.note!=="string"||body.note.trim().length<3||body.note.length>1000||!Number.isSafeInteger(body.version))fail(400,"triage_note_required");
  const r=await stmt(env,"UPDATE cs_findings SET triage=?,note=?,version=version+1 WHERE id=? AND owner=? AND project=? AND version=?",body.status,body.note.trim(),match[1],actor.id,project,body.version).run();
  if(r.meta.changes!==1)fail(409,"finding_changed");await audit(env,actor.id,project,"finding.triage",match[1]);return reply({ok:true});
 }
 if(path==="/api/fixes"&&method==="POST"){
  const v=await first(env,"SELECT f.*,r.evidence_sha256,r.target_version,r.status AS run_status FROM cs_findings f JOIN cs_runs r ON r.id=f.run_id WHERE f.id=? AND f.owner=? AND f.project=?",body.findingId,actor.id,project);
  if(!v||v.run_status!=="partial"||!v.evidence_sha256)fail(409,"finding_evidence_unavailable");
  const t=await target(env,actor.id,project,v.target_id);if(t.version!==v.target_version||t.paused)fail(409,"stale_finding");
  const finding=JSON.parse(v.data);if(!finding.header||!finding["suggested-value"])fail(409,"fix_not_supported");
  const id=crypto.randomUUID(),patch=JSON.stringify({schemaVersion:1,format:"response-header-configuration",target:t.url,
   findingId:v.id,runId:v.run_id,evidenceSha256:v.evidence_sha256,source:env.SOURCE_SHA,
   setHeaders:{[finding.header]:finding["suggested-value"]},
   reviewRequired:"Review route, embedding, resource compatibility and deployment configuration before applying.",
   applied:false},null,2);
  const old=await first(env,"SELECT id FROM cs_fixes WHERE owner=? AND project=? AND finding_id=?",actor.id,project,v.id);if(old)return reply(old);
  await stmt(env,"INSERT INTO cs_fixes(id,owner,project,finding_id,run_id,target_id,target_version,evidence_sha256,patch,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",id,actor.id,project,v.id,v.run_id,t.id,t.version,v.evidence_sha256,patch,Date.now()).run();
  await audit(env,actor.id,project,"fix.proposed",id);return reply({id,status:"proposed"},201);
 }
 match=path.match(/^\/api\/fixes\/([a-f0-9-]{36})\/(approve|reject|export)$/i);
 if(match&&method==="POST"){
  const x=await first(env,"SELECT * FROM cs_fixes WHERE id=? AND owner=? AND project=?",match[1],actor.id,project);if(!x)fail(404,"fix_not_found");
  const t=await target(env,actor.id,project,x.target_id);if(t.version!==x.target_version||t.paused)fail(409,"stale_fix");
  const next=match[2]==="approve"?"approved":match[2]==="reject"?"rejected":"exported";
  if(!engine.transition(x.status,next))fail(409,"fix_state_changed");
  if(next!=="exported"&&(typeof body.note!=="string"||body.note.trim().length<3||body.note.length>1000||body.reviewed!==true))fail(400,"review_required");
  const r=await stmt(env,"UPDATE cs_fixes SET status=?,reviewed_at=?,note=COALESCE(?,note) WHERE id=? AND owner=? AND project=? AND status=?",next,Date.now(),body.note?.trim()||null,x.id,actor.id,project,x.status).run();
  if(r.meta.changes!==1)fail(409,"fix_state_changed");await audit(env,actor.id,project,"fix."+match[2],x.id);
  return reply(next==="exported"?{id:x.id,status:next,filename:"mithril-security-headers-"+x.id+".json",patch:x.patch,applied:false}:{id:x.id,status:next});
 }
 fail(404,"not_found");
}
function secure(response,privatePage=false){
 const h=new Headers(response.headers);h.set("x-content-type-options","nosniff");h.set("referrer-policy","strict-origin-when-cross-origin");
 h.set("strict-transport-security","max-age=31536000");h.set("x-frame-options","DENY");
 h.set("permissions-policy","camera=(), microphone=(), geolocation=()");
 h.set("content-security-policy","default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
 if(privatePage)h.set("cache-control","no-store");return new Response(response.body,{status:response.status,headers:h});
}
export default {async fetch(req,env,ctx){
 try{
  const u=new URL(req.url);if(u.origin!==ORIGIN)fail(421,"host_not_allowed");
  if(u.pathname.startsWith("/api/"))return secure(await api(req,env,ctx),true);
  if(!["GET","HEAD"].includes(req.method))fail(405,"method_not_allowed");
  if(u.pathname==="/robots.txt"||u.pathname==="/sitemap.xml"){
   const robots=u.pathname==="/robots.txt";
   return secure(new Response(req.method==="HEAD"?null:robots?"User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /app\nSitemap: https://cs.mithril.fund/sitemap.xml\n":sitemap(),{headers:{"content-type":robots?"text/plain; charset=utf-8":"application/xml; charset=utf-8","cache-control":"public, max-age=300"}}));
  }
  if(u.pathname===social.path){
   const object=await env.EVIDENCE.get(social.key);
   if(!object)return secure(new Response("Image unavailable",{status:503,headers:{"cache-control":"no-store"}}));
   return secure(new Response(req.method==="HEAD"?null:object.body,{headers:{"content-type":"image/png","content-length":String(social.bytes),"cache-control":"public, max-age=31536000, immutable","etag":'"'+social.sha256+'"'}}));
  }
  const font=Object.hasOwn(fonts,u.pathname)?fonts[u.pathname]:null;
  if(font){
   const body=req.method==="HEAD"?null:Uint8Array.from(atob(font.base64),c=>c.charCodeAt(0));
   return secure(new Response(body,{headers:{"content-type":"font/woff2","content-length":String(font.bytes),"cache-control":"public, max-age=31536000, immutable","etag":'"'+font.sha256+'"'}}));
  }
  const asset=u.pathname==="/app.js"?[client,"text/javascript; charset=utf-8"]:u.pathname==="/style.css"?[css,"text/css; charset=utf-8"]:u.pathname==="/mithril.svg"?[logo,"image/svg+xml"]:null;
  if(asset)return secure(new Response(req.method==="HEAD"?null:asset[0],{headers:{"content-type":asset[1],"cache-control":"public, max-age=300"}}));
  const html=page(u);if(html===null)return secure(new Response("Page not found",{status:404}));
  return secure(new Response(req.method==="HEAD"?null:html,{headers:{"content-type":"text/html; charset=utf-8","cache-control":u.pathname.startsWith("/app")?"no-store":"no-cache"}}),u.pathname.startsWith("/app"));
 }catch(e){return secure(json({error:{code:e instanceof Failure?e.code:"temporarily_unavailable"}},e instanceof Failure?e.status:503),true);}
}};

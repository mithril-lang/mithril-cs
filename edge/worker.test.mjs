import test from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {readFileSync} from "node:fs";
import worker,{normalizeTarget,sha} from "./worker.mjs";
import engine from "./engine.mjs";
import vm from "node:vm";
import {client} from "./ui.mjs";
new vm.Script(client,{filename:"browser-client.js"});
const ORIGIN="https://cs.mithril.fund",A="a".repeat(32),B="b".repeat(32);
const schema=readFileSync(new URL("./schema.sql",import.meta.url),"utf8");
function fixture(){
 const db=new DatabaseSync(":memory:");db.exec(schema);const blobs=new Map(),jobs=[];
 let revoked=new Set(),fetches=[],responseMode="positive",held=null,badDNS=false;
 const DB={prepare(sql){let values=[];const s={bind(...v){values=v;return s;},
  async run(){try{const r=db.prepare(sql).run(...values);return {success:true,meta:{changes:Number(r.changes)}};}catch(e){console.error("SQL_TEST_FAILURE",sql,e.message);throw e;}},
  async first(){return db.prepare(sql).get(...values)||null;},
  async all(){return {results:db.prepare(sql).all(...values)};}};return s;},
  async batch(items){db.exec("BEGIN");try{const r=[];for(const x of items)r.push(await x.run());db.exec("COMMIT");return r;}catch(e){db.exec("ROLLBACK");throw e;}}};
 const env={DB,SOURCE_SHA:"3c64e42a1cc6db446b6bc65497e03adf96ea6bfc",ALLOWED_HOSTS:"mithril.fund,cs.mithril.fund",
  AUTH:{async fetch(req){const token=req.headers.get("cookie")?.slice(11);
   if(![A,B].includes(token)||revoked.has(token))return Response.json({error:"unauthenticated"},{status:401});
   if(new URL(req.url).pathname==="/v1/logout"){revoked.add(token);return Response.json({ok:true},{headers:{"set-cookie":"mf_session=; Max-Age=0; Domain=mithril.fund; Path=/; Secure; HttpOnly"}});}
   return Response.json({userId:token===A?"alice":"bob",assurance:"low"});}},
  WORKSPACE:{async fetch(req){const token=req.headers.get("cookie")?.slice(11);return Response.json({userId:token===A?"alice":"bob",documents:[{id:"owned-project",deleted:false}],nextAfter:null});}},
  EVIDENCE:{async put(k,v){blobs.set(k,v);},async get(k){const v=blobs.get(k);return v===undefined?null:{arrayBuffer:async()=>new TextEncoder().encode(v).buffer};}}};
 const ctx={waitUntil(p){jobs.push(p)}};
 globalThis.fetch=async (url,options={})=>{
  const u=new URL(url);
  if(u.hostname==="cloudflare-dns.com"){
   if(u.searchParams.get("type")==="TXT"){const host=u.searchParams.get("name").replace(/^_mithril-cs\./,"");
    const t=db.prepare("SELECT proof FROM cs_targets WHERE url=? ORDER BY created_at DESC LIMIT 1").get("https://"+host+"/");
    return Response.json({Status:0,Answer:t?[{type:16,data:'"mithril-cs='+t.proof+'"'}]:[]});}
   return Response.json({Status:0,Answer:u.searchParams.get("type")==="A"?[{type:1,data:badDNS?"127.0.0.1":"104.16.1.2"}]:[]});
  }
  fetches.push({url:u.href,headers:options.headers,method:options.method,redirect:options.redirect});
  assert.equal(options.headers.cookie,undefined);assert.equal(options.headers.authorization,undefined);
  if(responseMode==="held")return new Promise(resolve=>{held=resolve;});
  if(responseMode==="large")return new Response(new Uint8Array(1048577),{headers:{"content-type":"text/html"}});
  if(responseMode==="redirect")return new Response(null,{status:307,headers:{location:"https://foreign.invalid/"}});
  if(responseMode==="blocked")return new Response("blocked",{status:403,headers:{"content-type":"text/html"}});
  const headers=responseMode==="hardened"?Object.fromEntries(["strict-transport-security","x-content-type-options","content-security-policy","referrer-policy","x-frame-options"].map(k=>[k,k==="content-security-policy"?"default-src 'none'; frame-ancestors 'none'":"configured"])):{};
  return new Response("<!doctype html><title>Controlled response</title>",{headers:{"content-type":"text/html; charset=utf-8",...headers}});
 };
 const csrf=new Map();
 async function request(path,body,token=A,extra={}){
  const headers={cookie:"mf_session="+token,...extra};
  if(body!==undefined){headers.origin=extra.origin||ORIGIN;headers["content-type"]="application/json";headers["x-csrf-token"]=extra["x-csrf-token"]??csrf.get(token)??"";}
  const req=new Request(ORIGIN+path,{method:body===undefined?"GET":"POST",headers,body:body===undefined?undefined:JSON.stringify(body)});
  const response=await worker.fetch(req,env,ctx);let value;
  try{value=await response.clone().json();}catch{value=await response.clone().text();}
  if(path==="/api/session"&&response.ok)csrf.set(token,value.csrf);
  return {response,value};
 }
 async function ready(token=A,host="mithril.fund"){
  await request("/api/session",undefined,token);
  const made=await request("/api/targets",{url:"https://"+host+"/",label:"Company site",authorized:true},token);assert.equal(made.response.status,201,JSON.stringify(made.value));
  const verified=await request("/api/targets/"+made.value.id+"/verify",{},token);assert.equal(verified.response.status,200,JSON.stringify(verified.value));return verified.value;
 }
 async function complete(){await Promise.all(jobs.splice(0));}
 return {db,env,request,ready,complete,blobs,fetches,revoke:t=>revoked.add(t),mode:x=>responseMode=x,badDNS:x=>badDNS=x,release:()=>held?.(new Response("done",{headers:{"content-type":"text/html"}})),held:()=>!!held};
}
test("actual compiled portable rules keep partial coverage and framing alternatives",()=>{
 const result=engine.assess({url:"https://example.test/",status:200,headers:{"content-type":"text/html"},"body-complete":false});
 assert.equal(engine.limits["max-pages"],1);assert.equal(engine.limits["response-bytes"],1048576);assert.equal(engine.limits["run-deadline-ms"],25000);
 assert.equal(result.findings.length,5);assert.equal(result.coverage.status,"partial");assert.equal(result.coverage["body-complete"],false);
 assert.equal(engine.transition("cancelled","partial"),false);assert.equal(engine.transition("approved","exported"),true);
});
test("public routes, CSP, unknown routes, URL rejection and no implicit execution",async()=>{
 const f=fixture();for(const path of ["/","/features","/features/auto-fix","/enterprise","/blog","/blog/kubernetes-security-fundamentals","/pricing","/start","/app/targets","/app/runs","/app/findings","/app/fixes"]){
  const r=await f.request(path);assert.equal(r.response.status,200,path);assert.match(r.response.headers.get("content-security-policy"),/script-src 'self'/);
 }
 assert.equal((await f.request("/features/not-a-feature")).response.status,404);
 assert.equal(f.fetches.length,0);assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM cs_runs").get().n,0);
 for(const url of ["http://example.com/","https://127.0.0.1/","https://[::1]/","https://example.com:444/","https://user:pass@example.com/","https://example.com/?secret=x","https://example.com/remove"]){assert.throws(()=>normalizeTarget(url));}
});
test("session, CSRF, cross-site requests and per-session scope separation",async()=>{
 const f=fixture();assert.equal((await f.request("/api/targets",undefined,"invalid")).response.status,401);
 assert.equal((await f.request("/api/session")).response.status,200);assert.equal((await f.request("/api/session",undefined,B)).response.status,200);
 const create={url:"https://mithril.fund/",label:"test",authorized:true};
 assert.equal((await f.request("/api/targets",create,A,{"x-csrf-token":"0".repeat(64)})).response.status,403);
 assert.equal((await f.request("/api/targets",create,A,{origin:"https://evil.test"})).response.status,403);
 assert.equal((await f.request("/api/targets",create,A,{"sec-fetch-site":"same-site"})).response.status,403);
 const a=await f.request("/api/session"),b=await f.request("/api/session",undefined,B);
 assert.notEqual(a.value.scope,b.value.scope);
 assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM cs_targets").get().n,0);
});
test("tenant and project denial never reach target transport",async()=>{
 const f=fixture(),t=await f.ready();await f.request("/api/session",undefined,B);
 assert.equal((await f.request("/api/targets/"+t.id+"/verify",{},B)).response.status,404);
 assert.equal((await f.request("/api/runs",{targetId:t.id,operation:crypto.randomUUID(),authorized:true},B)).response.status,404);
 assert.equal((await f.request("/api/targets?project=foreign")).response.status,403);
 assert.equal((await f.request("/api/targets",undefined,B)).value.targets.length,0);assert.equal(f.fetches.length,0);
});
test("real adapter lifecycle persists receipts, proposals, reviewed export and idempotency",async()=>{
 const f=fixture(),t=await f.ready(),operation=crypto.randomUUID(),input={targetId:t.id,operation,authorized:true};
 const r=await f.request("/api/runs",input);assert.equal(r.response.status,202,JSON.stringify(r.value));
 const duplicate=await f.request("/api/runs",input);assert.equal(duplicate.value.id,r.value.id);
 await f.complete();assert.equal(f.fetches.length,1);assert.equal(f.fetches[0].redirect,"manual");assert.equal(f.fetches[0].method,"GET");
 const history=(await f.request("/api/runs")).value.runs;assert.equal(history[0].status,"partial",history[0].error);
 const report=history[0].report;assert.equal(report.source,f.env.SOURCE_SHA);assert.equal(report.coverage.status,"partial");assert.equal(report.bodyComplete,true);
 assert.equal(f.blobs.size,2);
 const fs=(await f.request("/api/findings")).value.findings;assert.equal(fs.length,5);
 assert.equal((await f.request("/api/findings/"+fs[0].id+"/triage",{status:"acknowledged",note:"Reviewed context; not exploit confirmation",version:1})).response.status,200);
 assert.equal((await f.request("/api/findings/"+fs[0].id+"/triage",{status:"dismissed",note:"stale edit",version:1})).response.status,409);
 const fix=(await f.request("/api/fixes",{findingId:fs[0].id})).value;
 assert.equal((await f.request("/api/fixes/"+fix.id+"/export",{})).response.status,409);
 assert.equal((await f.request("/api/fixes/"+fix.id+"/approve",{note:"Reviewed the scope and compatibility",reviewed:true})).response.status,200);
 const exported=await f.request("/api/fixes/"+fix.id+"/export",{});assert.equal(exported.response.status,200);
 assert.equal(exported.value.applied,false);assert.equal(JSON.parse(exported.value.patch).evidenceSha256,history[0].evidence_sha256);
 await f.request("/api/session",undefined,B);
 assert.equal((await f.request("/api/fixes/"+fix.id+"/export",{},B)).response.status,404);
 f.mode("hardened");await f.request("/api/runs",{targetId:t.id,operation:crypto.randomUUID(),authorized:true});await f.complete();
 const second=(await f.request("/api/runs")).value.runs[0];assert.equal(second.status,"partial");assert.equal(second.report.findings.length,0);
 assert.equal((await f.request("/api/findings")).value.findings.length,5,"historical findings retained");
 await f.request("/api/targets/"+t.id+"/pause",{paused:true});
 assert.equal((await f.request("/api/fixes/"+fix.id+"/export",{})).response.status,409);
});
test("large response, denied response and redirect never become clean application coverage",async()=>{
 for(const mode of ["large","blocked","redirect"]){const f=fixture(),t=await f.ready();f.mode(mode);
  await f.request("/api/runs",{targetId:t.id,operation:crypto.randomUUID(),authorized:true});await f.complete();
  const r=(await f.request("/api/runs")).value.runs[0];assert.equal(r.report.coverage.status,"partial");
  if(mode==="large"){assert.equal(r.report.bodyComplete,false);assert.equal(r.report.bytes,1048577);assert.equal(r.status,"partial");}
  else {assert.equal(r.status,"failed");assert.equal(r.report.findings.length,0);}
  assert.equal(f.fetches.length,1);
 }
});
test("private destination blocked before any target GET",async()=>{
 const f=fixture(),t=await f.ready();f.badDNS(true);await f.request("/api/runs",{targetId:t.id,operation:crypto.randomUUID(),authorized:true});await f.complete();
 assert.equal(f.fetches.length,0);assert.equal((await f.request("/api/runs")).value.runs[0].status,"failed");
});
test("cancellation and target-version fencing reject late findings",async()=>{
 const f=fixture(),t=await f.ready();f.mode("held");
 const r=await f.request("/api/runs",{targetId:t.id,operation:crypto.randomUUID(),authorized:true});
 for(let i=0;i<100&&!f.held();i++)await new Promise(setImmediate);assert.equal(f.held(),true);
 await f.request("/api/runs/"+r.value.id+"/cancel",{});f.release();await f.complete();
 assert.equal((await f.request("/api/runs")).value.runs[0].status,"cancelled");
 assert.equal((await f.request("/api/findings")).value.findings.length,0);
});
test("logout revocation rejects subsequent reads and writes",async()=>{
 const f=fixture();await f.request("/api/session");const r=await f.request("/api/logout",{});
 assert.equal(r.response.status,200);assert.match(r.response.headers.get("set-cookie"),/Max-Age=0/);
 assert.equal((await f.request("/api/targets")).response.status,401);
 assert.equal((await f.request("/api/targets",{url:"https://mithril.fund/",label:"x",authorized:true})).response.status,401);
});

test("expired accepted work reconciles to unknown without transport or clean coverage",async()=>{
 const f=fixture(),t=await f.ready(),id=crypto.randomUUID();
 f.db.prepare("INSERT INTO cs_runs(id,owner,project,target_id,target_version,operation,status,created_at,expires_at) VALUES(?,?,?,?,?,?,'queued',?,?)").run(id,"alice","personal",t.id,t.version,crypto.randomUUID(),Date.now()-50000,Date.now()-1000);
 const r=await f.request("/api/runs/"+id+"/reconcile",{});assert.equal(r.response.status,200);
 assert.equal((await f.request("/api/runs")).value.runs[0].status,"unknown");assert.equal(f.fetches.length,0);
});
test("pausing a target fences a late response and preserves the original receipt",async()=>{
 const f=fixture(),t=await f.ready();f.mode("held");
 await f.request("/api/runs",{targetId:t.id,operation:crypto.randomUUID(),authorized:true});
 for(let i=0;i<100&&!f.held();i++)await new Promise(setImmediate);assert.equal(f.held(),true);
 await f.request("/api/targets/"+t.id+"/pause",{paused:true});f.release();await f.complete();
 assert.equal((await f.request("/api/runs")).value.runs[0].status,"cancelled");
 assert.equal((await f.request("/api/findings")).value.findings.length,0);
 assert.equal((await f.request("/api/targets")).value.targets[0].version,t.version+1);
});

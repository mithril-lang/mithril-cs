// Manual owner-side provider verification. Never run with live credentials or
// inside PR/VKE jobs. Temporary secrets and generated evidence stay outside Git.
import {readFileSync,writeFileSync,mkdirSync,chmodSync,existsSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {checkout,billingStatus,portal,webhook,stripe,TEST_MERCHANT,TERMS} from '../edge/billing.mjs';
import engine from '../edge/engine.mjs';

const state=resolve(process.env.CS_SANDBOX_STATE||'');
if(!state.startsWith('/Users/')||!process.env.CS_SANDBOX_STATE)throw Error('Private owner state directory required');
const key=readFileSync(join(state,'sandbox-key.pending'),'utf8').trim();
if(!key.startsWith('sk_test_')&&!key.startsWith('rk_test_'))throw Error('Test key required');
const cfg=JSON.parse(readFileSync(join(state,'sandbox-resources.json'),'utf8'));
if(cfg.sandbox!==TEST_MERCHANT||cfg.live_modified!==false)throw Error('Pinned isolated sandbox required');
const source=process.env.CS_SOURCE_SHA;if(!/^[0-9a-f]{40}$/.test(source||''))throw Error('Exact source required');
mkdirSync(state,{recursive:true,mode:0o700});chmodSync(state,0o700);
const db=new DatabaseSync(join(state,'verification.sqlite'));chmodSync(join(state,'verification.sqlite'),0o600);
db.exec(readFileSync(new URL('../edge/schema.sql',import.meta.url),'utf8'));
const DB={prepare(sql){let values=[];const q={bind(...args){values=args;return q;},async first(){return db.prepare(sql).get(...values)||null;},async all(){return {results:db.prepare(sql).all(...values)};},async run(){return {meta:{changes:Number(db.prepare(sql).run(...values).changes)}};}};return q;}};
const env={DB,SOURCE_SHA:source,STRIPE_CS_KEY:key,STRIPE_CS_WEBHOOK_SECRET:readFileSync(join(state,'sandbox-webhook.pending'),'utf8').trim(),STRIPE_CS_PRICE:cfg.price,STRIPE_CS_PORTAL_CONFIG:cfg.portal,CS_BILLING_MODE:'test',CS_BILLING_ISOLATED_TEST:'true',CS_BILLING_TAX_READY:'true'};
const account=await stripe(env,'account');if(account.id!==TEST_MERCHANT)throw Error('Sandbox account mismatch');
const priorOwners=db.prepare("SELECT owner FROM cs_billing WHERE owner LIKE 'sandbox-MITHRIL-2517-%'").all();
if(priorOwners.length>1)throw Error('Multiple sandbox operations need owner reconciliation');
const owner=priorOwners[0]?.owner||'sandbox-MITHRIL-2517-'+randomUUID();
const receiptPath=join(state,'provider-verification.json');
const receipts=existsSync(receiptPath)?JSON.parse(readFileSync(receiptPath,'utf8')):[];
if(!Array.isArray(receipts)||receipts.length>2000)throw Error('Bounded receipt history required');
function receipt(kind,data={}){const r={kind,time:new Date().toISOString(),source,sandbox:TEST_MERCHANT,...data};receipts.push(r);writeFileSync(join(state,'provider-verification.json'),JSON.stringify(receipts,null,2),{mode:0o600});console.log(JSON.stringify(r));}
const port=18087;
const server=createServer(async(req,res)=>{
 try{
  if(req.url!=='/webhook'||req.method!=='POST'){res.writeHead(404);return res.end();}
  const parts=[];let size=0;for await(const p of req){size+=p.length;if(size>262144)throw Error('Payload limit');parts.push(p);}
  const result=await webhook(new Request('http://127.0.0.1:'+port+'/webhook',{method:'POST',headers:{'stripe-signature':req.headers['stripe-signature']||''},body:Buffer.concat(parts)}),env,engine.entitlement);
  receipt('signed-provider-webhook',{duplicate:!!result.duplicate});res.writeHead(200);res.end('ok');
 }catch(e){receipt('webhook-rejected',{code:e.code||'unknown'});res.writeHead(e.status||500);res.end('rejected');}
});
await new Promise((ok,no)=>{server.once('error',no);server.listen(port,'127.0.0.1',ok);});
const events='checkout.session.completed,checkout.session.async_payment_succeeded,customer.subscription.created,customer.subscription.updated,customer.subscription.deleted,invoice.paid,invoice.payment_failed,charge.refunded,charge.dispute.created,radar.early_fraud_warning.created';
const listener=spawn('stripe',['listen','--skip-update','--events',events,'--forward-to','http://127.0.0.1:'+port+'/webhook'],{env:{...process.env,STRIPE_API_KEY:key},stdio:['ignore','pipe','pipe']});
process.once('exit',()=>listener.kill('SIGTERM'));
// Do not persist CLI output: it contains the signing secret and raw event data.
let readyResolve;const ready=new Promise(ok=>readyResolve=ok);let output='';
function observe(chunk){output=(output+chunk.toString()).slice(-8192);if(output.includes('Ready!'))readyResolve();}
listener.stdout.on('data',observe);listener.stderr.on('data',observe);
listener.once('error',()=>readyResolve());listener.once('exit',code=>receipt('listener-exit',{exit:code}));
await Promise.race([ready,new Promise((_,no)=>setTimeout(()=>no(Error('Listener readiness timeout')),30000))]);
if(!output.includes('Ready!'))throw Error('Listener not ready');
const observedSecret=output.match(/whsec_[A-Za-z0-9]+/)?.[0];
if(observedSecret&&observedSecret!==env.STRIPE_CS_WEBHOOK_SECRET)throw Error('Listener signing identity mismatch');
output='';receipt('listener-ready',{transport:'Stripe CLI loopback forwarding; production public webhook not tested'});
const initial=await billingStatus(env,owner,engine.entitlement);if(!initial.ready)throw Error('Provider readiness required');
if(['pending','not_subscribed'].includes(initial.state)&&!initial.riskHold){
 const result=await checkout(env,owner,{acceptedTerms:TERMS,recurring:true,locale:'en'},engine.entitlement);
 writeFileSync(join(state,'provider-checkout.json'),JSON.stringify({owner,source,...result}),{mode:0o600});
 receipt('adapter-checkout-created',{entitled:(await billingStatus(env,owner,engine.entitlement)).entitled});
}else receipt('existing-operation-resumed',{state:initial.state,entitled:initial.entitled,riskHold:initial.riskHold});
let last='';const timer=setInterval(async()=>{
 try{const status=await billingStatus(env,owner,engine.entitlement),signature=JSON.stringify([status.state,status.entitled,status.riskHold,status.cancelAtPeriodEnd]);
  if(signature!==last){receipt('provider-subscription-readback',{state:status.state,entitled:status.entitled,riskHold:status.riskHold,cancelAtPeriodEnd:status.cancelAtPeriodEnd});last=signature;}
  if(status.entitled){const p=join(state,'provider-portal.json');if(!lastPortal){const result=await portal(env,owner,{locale:'en'});writeFileSync(p,JSON.stringify(result),{mode:0o600});lastPortal=true;receipt('adapter-portal-created');}}
 }catch(e){receipt('provider-check-failed',{code:e.code||e.message});}
},5000);let lastPortal=false;
let stopping=false;function stop(){if(stopping)return;stopping=true;clearInterval(timer);listener.kill('SIGTERM');server.close();receipt('controller-stopped');setTimeout(()=>process.exit(0),1000).unref();}
process.on('SIGINT',stop);process.on('SIGTERM',stop);setTimeout(stop,20*60*1000).unref();

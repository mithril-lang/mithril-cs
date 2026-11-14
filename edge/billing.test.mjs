import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {billingStatus,checkout,portal,reconcile,verifySignature,webhook,MERCHANT,TEST_MERCHANT,SERVICE,TERMS} from './billing.mjs';
import engine from './engine.mjs';
import worker from './worker.mjs';
const eligible=x=>engine.entitlement(x);
const digest=async s=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))].map(x=>x.toString(16).padStart(2,'0')).join('');
function fixture(){
 const db=new DatabaseSync(':memory:');db.exec(readFileSync(new URL('./schema.sql',import.meta.url),'utf8'));
 const DB={prepare(sql){let args=[];const q={bind(...v){args=v;return q;},async first(){return db.prepare(sql).get(...args)||null;},async all(){return {results:db.prepare(sql).all(...args)};},async run(){return {meta:{changes:Number(db.prepare(sql).run(...args).changes)}};}};return q;}};
 const calls=[],customers=new Map(),sessions=new Map(),subs=new Map(),invoices=new Map(),cache=new Map();
 let creates=0,customerCreates=0,merchant=MERCHANT,productId='prod_fixture',unit=2900,tax=true,badUrl=false,loseCheckout=false,hold=null,entered=null;
 const price={id:'price_fixture',currency:'usd',unit_amount:2900,recurring:{interval:'month',interval_count:1,usage_type:'licensed'}};
 const env={DB,SOURCE_SHA:'a'.repeat(40),STRIPE_CS_KEY:'rk_live_fixture_only',STRIPE_CS_WEBHOOK_SECRET:'fixture-signing-only',STRIPE_CS_PRICE:'price_fixture',STRIPE_CS_PORTAL_CONFIG:'bpc_fixture',CS_BILLING_MODE:'live',CS_BILLING_TAX_READY:'true',
  AUTH:{async fetch(req){const tok=req.headers.get('cookie')?.split('=')[1];return ['a'.repeat(32),'b'.repeat(32)].includes(tok)?Response.json({userId:tok[0]==='a'?'alice':'bob'}):Response.json({}, {status:401});}}};
 env.STRIPE_TRANSPORT=async(raw,opts)=>{
  const u=new URL(raw);assert.equal(u.origin,'https://api.stripe.com');assert.equal(opts.redirect,'error');assert.equal(opts.headers.cookie,undefined);
  const p=u.pathname.slice(4),form=new URLSearchParams(opts.body),key=opts.headers['idempotency-key'];calls.push({path:p,method:opts.method,key,body:opts.body?.toString()});
  if(key&&cache.has(key)){const v=cache.get(key);assert.equal(v.body,opts.body.toString());return Response.json(v.data);}
  let d;
  if(p==='account')d={id:merchant,charges_enabled:true};
  else if(p==='prices/price_fixture')d={...price,unit_amount:unit,active:true,product:productId,livemode:true};
  else if(p==='products/prod_fixture'||p==='products/mithril_cs_pro_v1')d={active:true,tax_code:'fixture_tax_code',metadata:{service:SERVICE},livemode:true};
  else if(p==='tax/registrations')d={data:tax?[{id:'taxreg_fixture',status:'active'}]:[],has_more:false};
  else if(p==='customers'&&opts.method==='POST'){d={id:'cus_fixture'+(++customerCreates),metadata:{service:form.get('metadata[service]'),owner:form.get('metadata[owner]')},livemode:true};customers.set(d.id,d);}
  else if(p.startsWith('customers/'))d=customers.get(p.slice(10));
  else if(p==='subscriptions')d={data:[...subs.values()].filter(s=>s.customer===u.searchParams.get('customer')),has_more:false};
  else if(p.startsWith('subscriptions/')){d=JSON.parse(JSON.stringify(subs.get(p.slice(14))));if(hold){const wait=hold;hold=null;entered();await wait;}}
  else if(p.startsWith('invoices/'))d=invoices.get(p.slice(9));
  else if(p==='checkout/sessions'&&opts.method==='POST'){
   assert.equal(form.get('mode'),'subscription');assert.equal(form.get('line_items[0][price]'),'price_fixture');assert.equal(form.get('line_items[0][quantity]'),'1');assert.equal(form.get('automatic_tax[enabled]'),'true');assert.equal(form.get('payment_method_types[0]'),null);
   d={id:'cs_fixture'+(++creates),customer:form.get('customer'),status:'open',url:badUrl?'https://foreign.invalid/pay':'https://checkout.stripe.com/c/pay_fixture',metadata:Object.fromEntries(['service','owner','operation','terms'].map(k=>[k,form.get('metadata['+k+']')])),livemode:true};sessions.set(d.id,d);
  }else if(p.startsWith('checkout/sessions/'))d=sessions.get(p.slice(18));
  else if(p==='billing_portal/configurations/bpc_fixture')d={active:true,metadata:{service:SERVICE},features:{subscription_cancel:{enabled:true,mode:'at_period_end'},subscription_update:{enabled:false},payment_method_update:{enabled:true},invoice_history:{enabled:true}},livemode:true};
  else if(p==='billing_portal/sessions'){assert.ok(customers.has(form.get('customer')));d={url:'https://billing.stripe.com/p/session_fixture',livemode:true};}
  else if(p.startsWith('charges/'))d={id:p.slice(8),customer:[...customers.keys()][0],livemode:true,amount_refunded:2900};
  else throw Error('Unexpected Stripe fixture path '+p);
  assert.ok(d,'missing provider object '+p);if(key)cache.set(key,{body:opts.body.toString(),data:d});
  if(p==='checkout/sessions'&&loseCheckout){loseCheckout=false;throw Error('simulated transport loss after provider commit');}
  return Response.json(d);
 };
 const consent={acceptedTerms:TERMS,recurring:true,locale:'ja'};
 async function pay(owner='alice'){
  const r=db.prepare('SELECT * FROM cs_billing WHERE owner=?').get(owner),ownerHash=await digest(owner);
  const sub={id:'sub_'+owner,customer:r.customer_id,status:'active',metadata:{service:SERVICE,owner:ownerHash},livemode:true,cancel_at_period_end:false,items:{data:[{quantity:1,price:{...price},current_period_end:Math.floor(Date.now()/1000)+3600}],has_more:false},latest_invoice:'in_'+owner};
  subs.set(sub.id,sub);invoices.set(sub.latest_invoice,{id:sub.latest_invoice,customer:r.customer_id,currency:'usd',parent:{subscription_details:{subscription:sub.id}},status:'paid',amount_remaining:0,livemode:true});sessions.get(r.checkout_id).status='complete';return sub;
 }
 async function event(type,object,eventId='evt_fixture',override={}){
  const raw=JSON.stringify({id:eventId,livemode:true,type,data:{object},...override});const time=Math.floor(Date.now()/1000);const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(env.STRIPE_CS_WEBHOOK_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);const sig=[...new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(time+'.'+raw)))].map(x=>x.toString(16).padStart(2,'0')).join('');
  return webhook(new Request('https://cs.mithril.fund/api/billing/webhook',{method:'POST',headers:{'stripe-signature':'t='+time+',v1='+sig},body:raw}),env,eligible);
 }
 return {env,db,calls,customers,sessions,subs,invoices,consent,pay,event,get creates(){return creates;},get customerCreates(){return customerCreates;},merchant(v){merchant=v;},product(v){productId=v;},unit(v){unit=v;},tax(v){tax=v;},badUrl(){badUrl=true;},lose(){loseCheckout=true;},pause(){let release;const wait=new Promise(r=>release=r);const ready=new Promise(r=>entered=r);hold=wait;return {ready,release};}};
}
test('provisioned custom Product ID is supported without accepting provider paths',async()=>{
 const f=fixture();f.product('mithril_cs_pro_v1');assert.equal((await billingStatus(f.env,'alice',eligible)).ready,true);
 for(const p of ['../account','https://foreign.invalid/p','mithril_cs_pro_v1/account']){f.product(p);assert.equal((await billingStatus(f.env,'alice',eligible)).ready,false);}
 assert.equal(f.calls.some(c=>c.path.includes('..')||c.path.includes('://')),false);
});
test('isolated test mode pins the separate sandbox and cannot change the live merchant',async()=>{
 const f=fixture();f.env.CS_BILLING_MODE='test';f.env.STRIPE_CS_KEY='rk_test_fixture_only';f.env.CS_BILLING_ISOLATED_TEST='true';f.merchant(TEST_MERCHANT);
 const transport=f.env.STRIPE_TRANSPORT;f.env.STRIPE_TRANSPORT=async(...args)=>{const d=await (await transport(...args)).json();return Response.json(JSON.parse(JSON.stringify(d,(k,v)=>k==='livemode'?false:v)));};
 assert.equal((await billingStatus(f.env,'alice',eligible)).ready,true);
 f.merchant(MERCHANT);assert.equal((await billingStatus(f.env,'alice',eligible)).ready,false);
 delete f.env.CS_BILLING_ISOLATED_TEST;assert.equal((await billingStatus(f.env,'alice',eligible)).ready,false);
 const live=fixture();live.merchant(TEST_MERCHANT);live.env.CS_BILLING_ISOLATED_TEST='true';assert.equal((await billingStatus(live.env,'alice',eligible)).ready,false);
});
test('billing missing credentials is unavailable without exposing secrets or calling Stripe',async()=>{const f=fixture();delete f.env.STRIPE_CS_KEY;const v=await billingStatus(f.env,'alice',eligible);assert.equal(v.ready,false);assert.equal(v.entitled,false);assert.equal(f.calls.length,0);assert.equal(JSON.stringify(v).includes('fixture-signing'),false);});
test('billing requires merchant, fixed monthly price, mode and active tax registrations',async()=>{
 for(const mutate of [f=>f.merchant('acct_foreign'),f=>f.unit(2000),f=>f.tax(false),f=>f.env.STRIPE_CS_KEY='rk_test_fixture_only']){const f=fixture();mutate(f);const v=await billingStatus(f.env,'alice',eligible);assert.equal(v.ready,false);assert.equal(v.entitled,false);assert.equal(f.creates,0);}
});
test('billing requires explicit versioned terms and recurring consent',async()=>{const f=fixture();for(const c of [{},{acceptedTerms:TERMS},{acceptedTerms:'stale',recurring:true}])await assert.rejects(checkout(f.env,'alice',c,eligible),/billing_consent_required/);assert.equal(f.calls.length,0);});
test('simultaneous checkout retries create one customer and one Checkout; amount and owner cannot be injected',async()=>{const f=fixture();await Promise.all([checkout(f.env,'alice',{...f.consent,owner:'bob',amount:1},eligible),checkout(f.env,'alice',f.consent,eligible)]);assert.equal(f.customerCreates,1);assert.equal(f.creates,1);assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM cs_billing_consents').get().n,1);});
test('unknown Checkout outcome replays the same stable operation rather than creating a new payment',async()=>{const f=fixture();f.lose();await assert.rejects(checkout(f.env,'alice',f.consent,eligible),/simulated transport/);await checkout(f.env,'alice',f.consent,eligible);assert.equal(f.creates,1);assert.equal(f.customerCreates,1);});
test('unknown operation beyond idempotency retention is held for reconciliation',async()=>{const f=fixture();f.db.prepare('INSERT INTO cs_billing(owner,operation,operation_at,locale,terms,status) VALUES(?,?,?,?,?,?)').run('alice','old-operation',Date.now()-24*3600000,'ja',TERMS,'pending');await assert.rejects(checkout(f.env,'alice',f.consent,eligible),/billing_unknown/);assert.equal(f.creates,0);});
test('only an exact current paid subscription grants the compiled portable entitlement',async()=>{const f=fixture();await checkout(f.env,'alice',f.consent,eligible);assert.equal((await billingStatus(f.env,'alice',eligible)).entitled,false);const s=await f.pay();assert.equal((await billingStatus(f.env,'alice',eligible)).entitled,true);s.status='past_due';assert.equal((await billingStatus(f.env,'alice',eligible)).entitled,false);s.status='active';f.invoices.get(s.latest_invoice).status='open';assert.equal((await billingStatus(f.env,'alice',eligible)).entitled,false);});
test('period-end cancellation preserves paid access until actual expiry; duplicate subscription is denied',async()=>{const f=fixture();await checkout(f.env,'alice',f.consent,eligible);const s=await f.pay();s.cancel_at_period_end=true;assert.equal((await billingStatus(f.env,'alice',eligible)).entitled,true);await assert.rejects(checkout(f.env,'alice',f.consent,eligible),/billing_subscription_exists/);s.items.data[0].current_period_end=Math.floor(Date.now()/1000)-1;assert.equal((await billingStatus(f.env,'alice',eligible)).entitled,false);});
test('foreign invoice or modified seat/price never becomes a Pro entitlement',async()=>{for(const change of [f=>f.invoices.get('in_alice').customer='cus_foreign',f=>f.subs.get('sub_alice').items.data[0].quantity=2,f=>f.subs.get('sub_alice').items.data[0].price.id='price_foreign']){const f=fixture();await checkout(f.env,'alice',f.consent,eligible);await f.pay();change(f);assert.equal((await billingStatus(f.env,'alice',eligible)).entitled,false);}});
test('older concurrent verification cannot overwrite a newer failed-payment state',{timeout:5000},async()=>{const f=fixture();await checkout(f.env,'alice',f.consent,eligible);const s=await f.pay();const pause=f.pause();const old=reconcile(f.env,'alice',eligible);await pause.ready;s.status='past_due';await reconcile(f.env,'alice',eligible);pause.release();await assert.rejects(old,/billing_verification_superseded/);assert.equal(f.db.prepare('SELECT status FROM cs_billing').get().status,'past_due');});
test('signed lifecycle notifications are idempotent and ignore stale payload status',async()=>{const f=fixture();await checkout(f.env,'alice',f.consent,eligible);const s=await f.pay();s.status='past_due';await f.event('customer.subscription.updated',{customer:s.customer,status:'active'},'evt_old');assert.equal((await billingStatus(f.env,'alice',eligible)).entitled,false);const v=await f.event('customer.subscription.updated',{customer:s.customer,status:'active'},'evt_old');assert.equal(v.duplicate,true);assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM cs_billing_events').get().n,1);});
test('refund, dispute and early fraud events fence access; later paid events cannot remove that hold',async()=>{for(const type of ['charge.refunded','charge.dispute.created','radar.early_fraud_warning.created']){const f=fixture();await checkout(f.env,'alice',f.consent,eligible);const s=await f.pay();await f.event(type,{id:'ch_fixture',charge:'ch_fixture'},'evt_risk');await f.event('invoice.paid',{customer:s.customer},'evt_later');const v=await billingStatus(f.env,'alice',eligible);assert.equal(v.entitled,false);assert.equal(v.riskHold,true);}});
test('webhook forged, stale and wrong-mode payloads are rejected without a grant',async()=>{const f=fixture();await assert.rejects(verifySignature('{}','t=1000000000,v1='+'0'.repeat(64),'fixture',Date.now()),/expired/);await assert.rejects(webhook(new Request('https://cs.mithril.fund/api/billing/webhook',{method:'POST',headers:{'stripe-signature':'forged'},body:'{}'}),f.env,eligible),/signature_invalid/);await assert.rejects(f.event('invoice.paid',{customer:'cus_unknown'},'evt_wrongmode',{livemode:false}),/mode_mismatch/);});
test('portal binds the caller customer and locale and remains available for cancellation during a tax hold',async()=>{const f=fixture();await checkout(f.env,'alice',f.consent,eligible);f.env.CS_BILLING_TAX_READY='false';assert.equal((await billingStatus(f.env,'alice',eligible)).portalAvailable,true);const v=await portal(f.env,'alice',{locale:'ja',customer:'cus_foreign',return_url:'https://foreign.invalid'});assert.equal(new URL(v.url).hostname,'billing.stripe.com');const call=f.calls.find(x=>x.path==='billing_portal/sessions');const body=new URLSearchParams(call.body);assert.equal(body.get('customer'),f.db.prepare('SELECT customer_id FROM cs_billing WHERE owner=?').get('alice').customer_id);assert.equal(body.get('return_url'),'https://cs.mithril.fund/app/billing?lang=ja');await assert.rejects(portal(f.env,'bob'),/subscription_missing/);});
test('an untrusted provider payment URL is never returned for browser navigation',async()=>{const f=fixture();f.badUrl();await assert.rejects(checkout(f.env,'alice',f.consent,eligible),/billing_provider_invalid/);});
test('billing API enforces actual session and CSRF; bulk export is denied without paid entitlement',async()=>{const f=fixture();const origin='https://cs.mithril.fund';const context={waitUntil(){}};
 let r=await worker.fetch(new Request(origin+'/api/billing'),f.env,context);assert.equal(r.status,401);
 r=await worker.fetch(new Request(origin+'/api/billing/checkout',{method:'POST',headers:{cookie:'mf_session='+'a'.repeat(32),origin,'content-type':'application/json'},body:JSON.stringify(f.consent)}),f.env,context);assert.equal(r.status,403);assert.equal(f.creates,0);
 const s=await (await worker.fetch(new Request(origin+'/api/session',{headers:{cookie:'mf_session='+'a'.repeat(32)}}),f.env,context)).json();
 r=await worker.fetch(new Request(origin+'/api/billing/reports',{method:'POST',headers:{cookie:'mf_session='+'a'.repeat(32),origin,'content-type':'application/json','x-csrf-token':s.csrf},body:'{}'}),f.env,context);assert.equal(r.status,403);
});

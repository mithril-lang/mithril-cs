// Fixed merchant/SKU adapter. Provider credentials never enter browser state.
export const TERMS='cs-pro-20261114-v1';
export const MERCHANT='acct_1U7sRyITDawH5x8a';
// Dedicated Kotoba Labs sandbox; never selected by the production entrypoint.
export const TEST_MERCHANT='acct_1Ubf2TIJVnMCo3dC';
export const SERVICE='mithril-cs-pro-v1';
const ORIGIN='https://cs.mithril.fund';
export class BillingError extends Error {constructor(status,code){super(code);this.status=status;this.code=code;}}
const stop=(code,status=409)=>{throw new BillingError(status,code)};
const id=(v,p)=>{if(typeof v!=='string'||!new RegExp('^'+p+'_'+(p==='cs'?'(?:test_|live_)':'')+'[A-Za-z0-9]+$').test(v))stop('billing_provider_invalid',503);return v;};
const q=(env,sql,...values)=>env.DB.prepare(sql).bind(...values);
const row=(env,owner)=>q(env,'SELECT * FROM cs_billing WHERE owner=?',owner).first();
const hash=async value=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)))].map(x=>x.toString(16).padStart(2,'0')).join('');
async function readText(response){
 const reader=response.body?.getReader();if(!reader)return '';const parts=[];let size=0;
 try{while(true){const r=await reader.read();if(r.done)break;size+=r.value.length;if(size>262144)stop('billing_response_limit',413);parts.push(r.value);}}finally{await reader.cancel().catch(()=>{});}
 const all=new Uint8Array(size);let at=0;for(const p of parts){all.set(p,at);at+=p.length;}return new TextDecoder().decode(all);
}
function fields(value,prefix='',out=new URLSearchParams()){
 for(const [key,v]of Object.entries(value)){if(v===undefined||v===null)continue;const name=prefix?prefix+'['+key+']':key;
  if(typeof v==='object')fields(v,name,out);else out.set(name,String(v));}return out;
}
function mode(env){if(!['live','test'].includes(env.CS_BILLING_MODE))stop('billing_setup_pending',503);return env.CS_BILLING_MODE==='live';}
function hasRuntime(env){
 return !!(env.STRIPE_CS_KEY&&env.STRIPE_CS_WEBHOOK_SECRET&&env.STRIPE_CS_PRICE&&env.STRIPE_CS_PORTAL_CONFIG&&(env.CS_BILLING_MODE==='live'||env.CS_BILLING_MODE==='test'&&env.CS_BILLING_ISOLATED_TEST==='true') );
}
function configured(env){return hasRuntime(env)&&env.CS_BILLING_TAX_READY==='true';}
export async function stripe(env,path,body,key){
 const live=mode(env);if(!new RegExp('^(sk|rk)_'+(live?'live':'test')+'_').test(env.STRIPE_CS_KEY||''))stop('billing_setup_pending',503);
 // Test keys require a separately provisioned isolated owner fixture, never production.
 if(!live&&env.CS_BILLING_ISOLATED_TEST!=='true')stop('billing_mode_denied',503);
 if(!/^[a-z_]+(?:\/[A-Za-z0-9_]+)*$/.test(path))stop('billing_provider_invalid',503);
 const response=await (env.STRIPE_TRANSPORT||fetch)('https://api.stripe.com/v1/'+path,{method:body?'POST':'GET',redirect:'error',signal:AbortSignal.timeout(12000),
  headers:{authorization:'Bearer '+env.STRIPE_CS_KEY,'stripe-version':'2026-09-30.endive',...(body?{'content-type':'application/x-www-form-urlencoded'}:{}),...(key?{'idempotency-key':key}:{})},body:body?fields(body):undefined});
 const raw=await readText(response);let data;try{data=JSON.parse(raw);}catch{stop('billing_provider_invalid',503);}
 if(!response.ok)stop('billing_provider_unavailable',503);if(data.livemode!==undefined&&data.livemode!==live)stop('billing_mode_mismatch',503);return data;
}
async function list(env,path,query){
 // Query is constructed here; callers cannot select another host or endpoint.
 const data=await stripe({...env,STRIPE_TRANSPORT:async(url,options)=>{
  const u=new URL(url);for(const [k,v]of Object.entries(query))u.searchParams.set(k,String(v));return (env.STRIPE_TRANSPORT||fetch)(u.href,options);
 }},path);if(!Array.isArray(data.data)||data.has_more)stop('billing_provider_incomplete',503);return data.data;
}
export async function readiness(env){
 if(!configured(env))return false;
 // A separate Sandbox can create test Checkout while charges_enabled is false
 // (observed on our empty sandbox). Live acquisition still requires it true.
 const account=await stripe(env,'account');if(account.id!==(mode(env)?MERCHANT:TEST_MERCHANT)||(mode(env)&&account.charges_enabled!==true))stop('billing_merchant_mismatch',503);
 const price=await stripe(env,'prices/'+id(env.STRIPE_CS_PRICE,'price'));
 if(!price.active||price.currency!=='usd'||price.unit_amount!==2900||price.recurring?.interval!=='month'||price.recurring?.interval_count!==1||price.recurring?.usage_type!=='licensed')stop('billing_price_mismatch',503);
 const productId=typeof price.product==='string'?price.product:price.product?.id;
 // Stripe also allows merchant-defined Product IDs. Accept only our exact
 // provisioned custom ID in addition to standard prod_ IDs, never a URL/path.
 const product=await stripe(env,'products/'+(productId==='mithril_cs_pro_v1'?productId:id(productId,'prod')));
 if(product.metadata?.service!==SERVICE||!product.active||!product.tax_code)stop('billing_product_mismatch',503);
 const registrations=await list(env,'tax/registrations',{status:'active',limit:100});if(!registrations.length)stop('billing_tax_setup_pending',503);
 return true;
}
const safe=(r,entitled=false)=>({state:r?.status||'not_subscribed',entitled,priceUsdCents:2900,seats:1,interval:'month',periodEnd:r?.period_end||null,cancelAtPeriodEnd:!!r?.cancel_at_period_end,riskHold:!!r?.risk_hold,verifiedAt:r?.verified_at||null});
async function subscriptions(env,r){
 if(!r.customer_id)return [];
 const values=await list(env,'subscriptions',{customer:id(r.customer_id,'cus'),status:'all',limit:100});
 const owner=await hash(r.owner);return values.filter(s=>s.metadata?.service===SERVICE&&s.metadata?.owner===owner);
}
const openStatus=new Set(['active','trialing','past_due','unpaid','incomplete','paused']);
export async function reconcile(env,owner,entitlement){
 let r=await row(env,owner);if(!r?.customer_id)return safe(r);
 const fence=crypto.randomUUID();await q(env,'UPDATE cs_billing SET verification_token=? WHERE owner=? AND customer_id=?',fence,owner,r.customer_id).run();
 const all=await subscriptions(env,r),open=all.filter(s=>openStatus.has(s.status));if(open.length>1)stop('billing_multiple_subscriptions',503);
 const candidate=open[0]||all.find(s=>s.id===r.subscription_id);if(!candidate)return safe(r);
 const s=await stripe(env,'subscriptions/'+id(candidate.id,'sub'));
 if(s.customer!==r.customer_id||s.metadata?.service!==SERVICE||s.metadata?.owner!==await hash(owner))stop('billing_owner_mismatch',503);
 const items=s.items?.data;if(s.items?.has_more||items?.length!==1||items[0].quantity!==1||items[0].price?.id!==env.STRIPE_CS_PRICE||items[0].price?.currency!=='usd'||items[0].price?.unit_amount!==2900)stop('billing_price_mismatch',503);
 const invoiceId=typeof s.latest_invoice==='string'?s.latest_invoice:s.latest_invoice?.id;
 let paid=false;if(invoiceId){const inv=await stripe(env,'invoices/'+id(invoiceId,'in'));const sub=inv.subscription||inv.parent?.subscription_details?.subscription;
  if(inv.customer!==r.customer_id||sub!==s.id||inv.currency!=='usd')stop('billing_invoice_mismatch',503);paid=inv.status==='paid'&&inv.amount_remaining===0;}
 const end=items[0].current_period_end??s.current_period_end;if(!Number.isSafeInteger(end)||end<=0)stop('billing_provider_invalid',503);
 const committed=await q(env,'UPDATE cs_billing SET subscription_id=?,status=?,paid=?,period_end=?,cancel_at_period_end=?,verified_at=? WHERE owner=? AND customer_id=? AND verification_token=?',s.id,s.status,paid?1:0,end,s.cancel_at_period_end?1:0,Date.now(),owner,r.customer_id,fence).run();
 if(committed.meta.changes!==1)stop('billing_verification_superseded',503);
 r=await row(env,owner);if(r.verification_token!==fence)stop('billing_verification_superseded',503);return safe(r,entitlement({status:r.status,paid:r.paid===1,risk:!!r.risk_hold,period_end:r.period_end,now:Math.floor(Date.now()/1000)}));
}
export async function billingStatus(env,owner,entitlement){
 const r=await row(env,owner),portalAvailable=!!r?.customer_id&&hasRuntime(env);
 try{if(!await readiness(env))return {...safe(r),ready:false,portalAvailable,entitled:false,code:'billing_setup_pending'};
  return {...await reconcile(env,owner,entitlement),ready:true,portalAvailable};
 }catch(e){if(e instanceof BillingError)return {...safe(r),ready:false,portalAvailable,entitled:false,code:e.code,state:'unknown'};throw e;}
}
function sameOwner(r,hashValue){return {service:SERVICE,owner:hashValue,operation:r.operation,terms:TERMS};}
export async function checkout(env,owner,body,entitlement){
 if(!body||body.acceptedTerms!==TERMS||body.recurring!==true)stop('billing_consent_required',400);
 if(!await readiness(env))stop('billing_setup_pending',503);
 const locale=body.locale==='ja'?'ja':'en',now=Date.now();
 await q(env,'INSERT OR IGNORE INTO cs_billing(owner,operation,operation_at,locale,terms,status) VALUES(?,?,?,?,?,?)',owner,crypto.randomUUID(),now,locale,TERMS,'pending').run();
 let r=await row(env,owner);if(r.risk_hold)stop('billing_review_required');
 if(r.customer_id){const current=await reconcile(env,owner,entitlement);if(current.entitled||openStatus.has(current.state))stop('billing_subscription_exists');}
 if(r.terms!==TERMS)stop('billing_terms_changed');
 const ownerHash=await hash(owner);
 if(r.checkout_id){const old=await stripe(env,'checkout/sessions/'+id(r.checkout_id,'cs'));
  if(old.customer!==r.customer_id||old.metadata?.owner!==ownerHash||old.metadata?.service!==SERVICE)stop('billing_owner_mismatch',503);
  if(old.status==='open'){return {url:providerUrl(old.url,'checkout.stripe.com'),reused:true};}
  if(!['expired','complete'].includes(old.status))stop('billing_unknown',503);
  await q(env,'UPDATE cs_billing SET operation=?,operation_at=?,locale=?,terms=?,checkout_id=NULL,status=? WHERE owner=? AND operation=? AND checkout_id=?',crypto.randomUUID(),now,locale,TERMS,'pending',owner,r.operation,r.checkout_id).run();r=await row(env,owner);
 }
 // A lost write beyond Stripe's idempotency retention needs explicit reconciliation.
 if(now-r.operation_at>23*3600000)stop('billing_unknown',503);
 await q(env,'INSERT OR IGNORE INTO cs_billing_consents(operation,owner,terms,source,accepted_at) VALUES(?,?,?,?,?)',r.operation,owner,r.terms,env.SOURCE_SHA,r.operation_at).run();
 if(!r.customer_id){const customer=await stripe(env,'customers',{metadata:{service:SERVICE,owner:ownerHash}},'cs-pro:customer:'+ownerHash+':'+r.operation);
  await q(env,'UPDATE cs_billing SET customer_id=? WHERE owner=? AND operation=? AND customer_id IS NULL',id(customer.id,'cus'),owner,r.operation).run();r=await row(env,owner);}
 const session=await stripe(env,'checkout/sessions',{mode:'subscription',ui_mode:'hosted_page',adaptive_pricing:{enabled:false},customer:r.customer_id,locale:r.locale,
  line_items:[{price:env.STRIPE_CS_PRICE,quantity:1}],automatic_tax:{enabled:true},billing_address_collection:'required',customer_update:{address:'auto'},
  integration_identifier:'mithril-cs-pro-qtxpvjrw',client_reference_id:ownerHash,metadata:sameOwner(r,ownerHash),subscription_data:{metadata:sameOwner(r,ownerHash)},
  success_url:ORIGIN+'/app/billing?lang='+r.locale+'&checkout=return',cancel_url:ORIGIN+'/app/billing?lang='+r.locale+'&checkout=cancelled'},'cs-pro:checkout:'+r.operation);
 if(session.customer!==r.customer_id||session.metadata?.owner!==ownerHash||session.metadata?.operation!==r.operation)stop('billing_provider_invalid',503);
 await q(env,'UPDATE cs_billing SET checkout_id=? WHERE owner=? AND operation=? AND customer_id=?',id(session.id,'cs'),owner,r.operation,r.customer_id).run();
 return {url:providerUrl(session.url,'checkout.stripe.com'),reused:false};
}
function providerUrl(raw,host){let u;try{u=new URL(raw);}catch{stop('billing_provider_invalid',503);}if(u.protocol!=='https:'||u.hostname!==host||u.username||u.password||u.port)stop('billing_provider_invalid',503);return u.href;}
export async function portal(env,owner,body={}){
 if(!hasRuntime(env))stop('billing_setup_pending',503);const r=await row(env,owner);if(!r?.customer_id)stop('billing_subscription_missing');
 const config=await stripe(env,'billing_portal/configurations/'+id(env.STRIPE_CS_PORTAL_CONFIG,'bpc'));
 if(!config.active||config.metadata?.service!==SERVICE||config.features?.subscription_cancel?.enabled!==true||config.features?.subscription_cancel?.mode!=='at_period_end'||!config.features?.payment_method_update?.enabled||!config.features?.invoice_history?.enabled||config.features?.subscription_update?.enabled)stop('billing_portal_mismatch',503);
 const customer=await stripe(env,'customers/'+id(r.customer_id,'cus'));if(customer.metadata?.service!==SERVICE||customer.metadata?.owner!==await hash(owner))stop('billing_owner_mismatch',503);
 const s=await stripe(env,'billing_portal/sessions',{customer:r.customer_id,configuration:env.STRIPE_CS_PORTAL_CONFIG,return_url:ORIGIN+'/app/billing?lang='+(body.locale==='ja'?'ja':'en')});
 return {url:providerUrl(s.url,'billing.stripe.com')};
}
export async function verifySignature(raw,header,secret,now=Date.now()){
 if(!secret||typeof header!=='string')stop('billing_signature_invalid',400);const parts=header.split(',');const ts=parts.filter(x=>x.startsWith('t='));const signatures=parts.filter(x=>/^v1=[a-f0-9]{64}$/.test(x)).map(x=>x.slice(3));
 if(ts.length!==1||!/^t=\d{10,}$/.test(ts[0])||!signatures.length)stop('billing_signature_invalid',400);const t=Number(ts[0].slice(2));if(now/1000-t>300||t-now/1000>30)stop('billing_signature_expired',400);
 const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['verify']);
 for(const s of signatures)if(await crypto.subtle.verify('HMAC',key,Uint8Array.from(s.match(/../g),x=>parseInt(x,16)),new TextEncoder().encode(t+'.'+raw)))return true;
 stop('billing_signature_invalid',400);
}
const lifecycle=new Set(['checkout.session.completed','checkout.session.async_payment_succeeded','customer.subscription.created','customer.subscription.updated','customer.subscription.deleted','invoice.paid','invoice.payment_failed']);
const risks=new Set(['charge.refunded','charge.dispute.created','radar.early_fraud_warning.created']);
export async function webhook(req,env,entitlement){
 if(!env.STRIPE_CS_WEBHOOK_SECRET)stop('billing_setup_pending',503);const raw=await readText(req);await verifySignature(raw,req.headers.get('stripe-signature'),env.STRIPE_CS_WEBHOOK_SECRET);
 let event;try{event=JSON.parse(raw);}catch{stop('billing_event_invalid',400);}if(event.livemode!==mode(env))stop('billing_mode_mismatch',400);id(event.id,'evt');
 if(!lifecycle.has(event.type)&&!risks.has(event.type))return {received:true,ignored:true};
 if(await q(env,"SELECT id FROM cs_billing_events WHERE id=? AND status='processed'",event.id).first())return {received:true,duplicate:true};
 const object=event.data?.object;if(!object)stop('billing_event_invalid',400);let customer=object.customer;
 if(risks.has(event.type)){const charge=await stripe(env,'charges/'+id(event.type==='charge.refunded'?object.id:object.charge,'ch'));customer=charge.customer;}
 if(!customer)return {received:true,ignored:true};id(customer,'cus');const r=await q(env,'SELECT * FROM cs_billing WHERE customer_id=?',customer).first();if(!r)return {received:true,ignored:true};
 // Risk fencing is monotonic; later paid/old events cannot restore access.
 if(risks.has(event.type))await q(env,'UPDATE cs_billing SET risk_hold=1 WHERE owner=? AND customer_id=?',r.owner,customer).run();
 await reconcile(env,r.owner,entitlement);
 await q(env,"INSERT INTO cs_billing_events(id,event_type,status,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status",event.id,event.type,'processed',Date.now()).run();return {received:true};
}

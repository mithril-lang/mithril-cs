export function billingPage(ja,query){return `<section class="cs-reading cs-billing"><a href="/pricing${query}">← ${ja?'料金プラン':'Pricing'}</a><div id="billing-root" aria-live="polite" aria-busy="true"><h1>${ja?'Proの申込と契約':'Pro subscription'}</h1><p>${ja?'ログイン状態を確認しています…':'Checking your session…'}</p></div></section>`;}
function browserBilling(){
 const root=document.querySelector('#billing-root');if(!root)return;
 const ja=document.documentElement.lang==='ja',t=(en,jp)=>ja?jp:en;
 const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 let session=null,epoch=0,busy=false,polls=0,timer;
 const query='?lang='+(ja?'ja':'en');
 async function call(path,body){
  const current=epoch,expected=session?.scope;
  const r=await fetch('/api/'+path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',headers:body?{'content-type':'application/json','x-csrf-token':session?.csrf||''}:{},body:body?JSON.stringify(body):undefined});
  const v=await r.json();if(current!==epoch)throw Error('actor_changed');
  if(!r.ok){if(r.status===401||r.status===403){session=null;root.replaceChildren();}const e=Error(v.error?.code||'billing_unavailable');e.status=r.status;throw e;}
  if(path!=='session'&&expected!==r.headers.get('x-mithril-scope')){session=null;root.replaceChildren();throw Error('actor_changed');}return v;
 }
 function error(e){
  const node=document.createElement('p');node.className='error';node.setAttribute('role','alert');node.textContent=t('The operation could not be confirmed. Refresh the subscription status before trying again. ','処理を確認できませんでした。再度申し込まず、契約状態を更新してください。')+esc(e.message);root.prepend(node);
 }
 async function redirect(kind,body){
  if(busy)return;busy=true;const version=epoch;root.querySelectorAll('button').forEach(b=>b.disabled=true);
  try{const scope=session.scope;const v=await call('billing/'+kind,body);const now=await call('session');if(version!==epoch||scope!==now.scope)throw Error('actor_changed');
   const url=new URL(v.url);if(url.protocol!=='https:'||!['checkout.stripe.com','billing.stripe.com'].includes(url.hostname)||url.username||url.password||url.port)throw Error('invalid_payment_destination');location.assign(url.href);
  }catch(e){error(e);root.querySelectorAll('button').forEach(b=>b.disabled=false);}finally{busy=false;}
 }
 function login(){
  session=null;clearTimeout(timer);root.innerHTML='<h1>'+t('Sign in to start Pro','Proをはじめる')+'</h1><p>'+t('Use your existing Mithril account. Payment information is entered only on Stripe.','既存のMithrilアカウントを使用します。支払い情報はStripe画面で入力します。')+'</p><button class="primary" id="billing-login">'+t('Sign in','ログイン')+'</button><p id="billing-login-status" role="status"></p>';
  root.querySelector('#billing-login').onclick=()=>{const popup=window.open('https://auth.mithril.fund/sign-in','mithril-cs-sign-in','popup,width=600,height=760');root.querySelector('#billing-login-status').textContent=t('Complete sign-in, then return here.','ログインを完了し、この画面へ戻ってください。');
   let n=0;const check=setInterval(async()=>{if(++n>120){clearInterval(check);return;}try{const v=await call('session');if(v.signedIn){clearInterval(check);if(popup&&!popup.closed)popup.close();await load();}}catch{}},3000);};
 }
 async function load(){
  if(busy)return;const version=++epoch;clearTimeout(timer);root.setAttribute('aria-busy','true');root.innerHTML='<p>'+t('Checking subscription…','契約状態を確認しています…')+'</p>';
  try{session=await call('session');const v=await call('billing');if(version!==epoch)return;render(v);root.removeAttribute('aria-busy');
   if(v.state==='pending'&&new URL(location.href).searchParams.get('checkout')==='return'&&polls++<12)timer=setTimeout(load,5000);
  }catch(e){root.removeAttribute('aria-busy');if(e.status===401){login();return;}error(e);const b=document.createElement('button');b.textContent=t('Refresh','更新');b.onclick=load;root.append(b);}
 }
 function render(v){
  const label=v.entitled?t('Pro is active','Proをご利用いただけます'):v.riskHold?t('Review required','契約の確認が必要です'):v.state==='past_due'||v.state==='unpaid'?t('Update your payment method','お支払いを確認してください'):v.cancelAtPeriodEnd?t('Cancellation scheduled','解約予約済み'):t('Pro subscription','Proの申込と契約');
  root.innerHTML='<div class="row"><h1>'+label+'</h1><button id="billing-refresh">'+t('Refresh status','状態を更新')+'</button></div><section class="cs-evidence"><p class="cs-eyebrow">MITHRIL CONTINUOUS SECURITY</p><h2>Pro <span class="status">'+esc(v.state)+'</span></h2><p class="cs-price">$29 <small>'+t('/ month · 1 seat','／月・1席')+'</small></p><p>'+t('Monthly renewal. Pentests are billed separately.','毎月自動更新。Pentestは別料金です。')+'</p>'+(v.periodEnd?'<p>'+t('Current period ends: ','現在の契約期間の終了：')+esc(new Date(v.periodEnd*1000).toLocaleString(ja?'ja-JP':'en-US'))+'</p>':'')+(v.cancelAtPeriodEnd?'<p class="notice">'+t('Renewal is canceled. Access continues until the paid period ends.','次回の更新は解約予約済みです。支払い済み期間の終了まで利用できます。')+'</p>':'')+'</section>';
  root.querySelector('#billing-refresh').onclick=load;
  if(!v.ready&&v.portalAvailable){root.insertAdjacentHTML('beforeend','<p><button id="billing-held-portal">'+t('Manage subscription on Stripe','Stripeで契約を管理')+'</button></p>');root.querySelector('#billing-held-portal').onclick=()=>redirect('portal',{locale:ja?'ja':'en'});}
  if(!v.ready){root.insertAdjacentHTML('beforeend','<p class="notice">'+t('New subscriptions are not available yet. No payment has been started.','現在、新規申込を受け付けていません。お支払いは開始されていません。')+'</p><a href="https://mithril.fund/support/contact'+query+'">'+t('Contact Mithril','お問い合わせ')+'</a>');return;}
  if(v.entitled){root.insertAdjacentHTML('beforeend','<p><a class="cs-button" href="/app/targets'+query+'">'+t('Open workspace','管理画面を開く')+'</a></p><button id="pro-export">'+t('Export recent reports','直近のレポートをまとめて出力')+'</button>');root.querySelector('#pro-export').onclick=async()=>{try{const v=await call('billing/reports',{});const url=URL.createObjectURL(new Blob([JSON.stringify(v,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='mithril-cs-pro-reports.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){error(e);}};}
  if(v.state!=='not_subscribed'&&v.state!=='pending'){root.insertAdjacentHTML('beforeend','<p><button id="billing-portal">'+t('Manage subscription on Stripe','Stripeで契約を管理')+'</button></p>');root.querySelector('#billing-portal').onclick=()=>redirect('portal',{locale:ja?'ja':'en'});}
  if(v.code)root.insertAdjacentHTML('beforeend','<p class="notice">'+t('Current subscription status needs confirmation. New payment is unavailable until reconciled.','現在の契約状態を確認する必要があります。照合できるまで、新しい支払いは開始できません。')+'</p>');
  if(!v.entitled&&!v.riskHold&&!v.code&&['not_subscribed','pending','canceled','incomplete_expired'].includes(v.state)){
   root.insertAdjacentHTML('beforeend','<p class="notice">'+t('Current testing is limited to approved company origins, one passive URL response and configured public repositories. Purchasing Pro does not authorize any target or enable active testing.','現在の検査は承認済みの自社オリジン、単一URLの受動的な応答確認と設定済み公開リポジトリに限られます。Proの購入だけで対象への権限や能動検査は有効になりません。')+'</p><form id="pro-checkout" class="editor"><label class="check"><input type="checkbox" name="terms" required>'+t('I agree to the terms and privacy policy and understand the current testing scope.','利用規約とプライバシーポリシー、現在の検査範囲を確認しました。')+'</label><p><a href="https://mithril.fund/legal/terms">'+t('Terms','利用規約')+'</a> · <a href="https://mithril.fund/legal/privacy">'+t('Privacy','プライバシー')+'</a></p><label class="check"><input type="checkbox" name="recurring" required>'+t('I authorize a monthly $29 subscription for one seat, plus any taxes shown on Stripe. It renews until canceled.','1席・月額$29とStripe画面で表示される税額の支払い、解約までの毎月の自動更新を確認しました。')+'</label><button class="primary" type="submit">'+t('Continue to Stripe','Stripeで支払いへ')+'</button></form>');
   root.querySelector('#pro-checkout').onsubmit=e=>{e.preventDefault();const f=e.currentTarget;if(!f.reportValidity())return;redirect('checkout',{acceptedTerms:'cs-pro-20261114-v1',recurring:f.elements.recurring.checked,locale:ja?'ja':'en'});};
  }
 }
 document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!busy)load();});load();
}
export const billingClient='('+browserBilling.toString()+')();';

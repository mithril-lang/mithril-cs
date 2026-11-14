import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {client,page} from './ui.mjs';
const pause=()=>new Promise(r=>setImmediate(r));
async function until(fn){for(let i=0;i<50;i++){if(fn())return;await pause();}assert.fail('Client state did not settle');}
function fixture(){
 const events={},docEvents={},nodes={},calls=[],posts=[];let actor='alice',delay=false;const held=[];
 const location=new URL('https://cs.mithril.fund/app/reviews?lang=en');location.assign=()=>{};location.reload=()=>{};
 function node(){return {innerHTML:'',dataset:{},hidden:true,open:false,setAttribute(){},removeAttribute(){},addEventListener(){},querySelector(s){return s==='summary'?node():null;},querySelectorAll(){return [];},focus(){},contains(){return false;}};}
 const root=node(),records=node(),account=node();root.querySelector=s=>s==='#records'?records:s==='h1'||s==='#sign-in'||s==='#retry-load'?node():null;
 for(const key of ['.cs-site','#theme','#locale','#sign-out'])nodes[key]=node();Object.assign(nodes,{'#workspace':root,'#account-menu':account,'#records':records,'#retry-load':node(),'#sign-in':node()});
 const document={documentElement:{lang:'en',style:{}},querySelector:s=>nodes[s]||null,querySelectorAll:()=>[],addEventListener:(n,f)=>(docEvents[n]??=[]).push(f),activeElement:null};
 const window={addEventListener:(n,f)=>(events[n]??=[]).push(f)};
 const context={document,window,location,history:{pushState(_s,_t,url){location.href=new URL(url,location).href;}},localStorage:{getItem(){return null;},setItem(){}},matchMedia:()=>({matches:true}),URL,Response,console,crypto:globalThis.crypto,setInterval:()=>1,clearInterval(){},setTimeout,clearTimeout,BroadcastChannel:class{constructor(){context.channel=this;}postMessage(v){posts.push(v);}}};
 context.fetch=async(path)=>{calls.push(path);const owner=actor;if(delay&&!path.endsWith('session'))await new Promise(r=>held.push(r));if(owner==='signed-out')return Response.json({error:{code:'sign_in_required'}},{status:401});let value;
  if(path.endsWith('/session'))value={scope:owner,csrf:'fixture',capabilities:{publicReviewRepositories:['mithril-lang/mithril-cs']}};
  else if(path.endsWith('/infrastructure'))value={source:'a'.repeat(40),resources:[]};
  else {const name=path.split('/').pop();value={[name]:[]};}
  return Response.json(value,{headers:{'x-mithril-scope':owner}});
 };
 vm.runInNewContext(client,context);
 function click(path,extra={}){let prevented=false;const a={href:new URL(path,location).href,target:'',hasAttribute:()=>false};const event={button:0,target:{closest:()=>a},preventDefault(){prevented=true;},...extra};for(const fn of docEvents.click||[])fn(event);return prevented;}
 return {root,records,account,calls,posts,context,location,click,events,actor(v){actor=v;},hold(){delay=true;},release(){delay=false;held.splice(0).forEach(f=>f());},ready:()=>!account.hidden};
}
test('workspace navigation keeps one shell and validates data without repeating session bootstrap',async()=>{
 const f=fixture();await until(f.ready);assert.equal(f.calls.filter(x=>x==='/api/session').length,1);assert.equal(f.click('/app/coverage?lang=en'),true);await until(()=>f.root.innerHTML.includes('Continuous coverage')&&!f.root.innerHTML.includes('cs-loading'));
 assert.equal(f.calls.filter(x=>x==='/api/session').length,1);assert.equal(f.context.document.querySelector('#workspace'),f.root);assert.doesNotMatch(f.root.innerHTML,/id="refresh"|id="sign-out"|Checking your session/);
 assert.match(page(new URL('https://cs.mithril.fund/app/reviews?lang=en')),/id="account-menu"/);
});
test('a late previous view cannot overwrite the current navigation',async()=>{
 const f=fixture();await until(f.ready);f.hold();f.click('/app/coverage?lang=en');f.click('/app/infrastructure?lang=en');f.release();await until(()=>f.root.innerHTML.includes('Infrastructure')&&!f.root.innerHTML.includes('cs-loading'));assert.doesNotMatch(f.root.innerHTML,/Continuous coverage/);assert.equal(f.location.pathname,'/app/infrastructure');
});
test('changed actor scope clears private view and account actions instead of showing mixed data',async()=>{
 const f=fixture();await until(f.ready);f.actor('bob');f.click('/app/risk?lang=en');await until(()=>f.root.innerHTML.includes('Sign in to Mithril CS'));assert.equal(f.account.hidden,true);assert.doesNotMatch(f.root.innerHTML,/id="records"/);
});
test('modified, foreign-locale and unknown-route links retain native browser navigation',async()=>{
 const f=fixture();await until(f.ready);assert.equal(f.click('/app/runs?lang=en',{ctrlKey:true}),false);assert.equal(f.click('/app/runs?lang=ja'),false);assert.equal(f.click('/app-unrelated/runs?lang=en'),false);assert.equal(f.click('/app/missing?lang=en'),false);
 f.location.href='https://cs.mithril.fund/app/reports?lang=en';f.events.popstate[0]();await until(()=>f.root.innerHTML.includes('Security report')&&!f.root.innerHTML.includes('cs-loading'));assert.equal(f.location.pathname,'/app/reports');
});
test('cross-tab logout immediately removes records and hides the shared account menu',async()=>{
 const f=fixture();await until(f.ready);f.context.channel.onmessage({data:'signed-out'});assert.equal(f.account.hidden,true);assert.match(f.root.innerHTML,/Sign in to Mithril CS/);assert.doesNotMatch(f.root.innerHTML,/id="records"/);
});

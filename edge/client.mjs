import {workspaceClient} from "./workspaces.mjs";
export const client=workspaceClient+String.raw`
const ja=document.documentElement.lang==="ja",tr=(en,jp)=>ja?jp:en;
const $=(s,r=document)=>r.querySelector(s),esc=x=>String(x??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const site=$(".cs-site"),theme=$("#theme");
let selected;try{selected=localStorage.getItem("mithril-cs-theme");}catch{}
if(!["dark","light"].includes(selected))selected=matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";
function applyTheme(value){site.dataset.theme=value;document.documentElement.style.colorScheme=value;theme.setAttribute("aria-pressed",String(value==="dark"));}
applyTheme(selected);
theme.addEventListener("click",()=>{selected=site.dataset.theme==="dark"?"light":"dark";applyTheme(selected);try{localStorage.setItem("mithril-cs-theme",selected);}catch{}});
$("#locale").addEventListener("change",event=>{const u=new URL(location.href);u.searchParams.set("lang",event.target.value);location.assign(u.href);});
const root=$("#workspace");
if(root){
 let session=null,state=null,epoch=0,busy=false,timer=null,selection={};
 const tab=location.pathname.split("/")[2]||"pentesting";
 selection.run=new URL(location.href).searchParams.get("run");
 const statusNames={"queued":tr("Queued","待機中"),"running":tr("Running","実行中"),"partial":tr("Partial coverage","部分検査"),"failed":tr("Failed","失敗"),"cancelled":tr("Cancelled","中止"),"unknown":tr("Outcome unknown","結果不明"),"proposed":tr("Proposed","提案中"),"approved":tr("Approved · not applied","承認済み・未適用"),"rejected":tr("Rejected","却下"),"exported":tr("Exported · application unverified","出力済み・適用未確認"),"needs-review":tr("Needs review","要確認"),"acknowledged":tr("Acknowledged","確認済み"),"dismissed":tr("Dismissed","対象外")};
 const badge=x=>'<span class="status">'+esc(statusNames[x]||x)+"</span>";
 const date=x=>x?new Date(x).toLocaleString():tr("Not recorded","記録なし");
 const names={targets:tr("Targets","検査対象"),runs:tr("Run history","実行履歴"),findings:tr("Findings","検出結果"),fixes:"Auto-Fix",pentesting:tr("Autonomous pentesting","自律ペンテスト"),reviews:tr("Pull request review","PRレビュー"),coverage:tr("Continuous coverage","継続監視"),infrastructure:tr("Infrastructure","インフラ"),reports:tr("Security report","セキュリティレポート"),risk:tr("Findings and risk","検出結果とリスク")};
 const errors={
  github_snapshot_unavailable:tr("No recent verified public-source snapshot is available. Refresh the source through the repository integration before retrying.","新しい検証済み公開ソースのスナップショットがありません。リポジトリ連携でソースを更新後、再試行してください。"),
  github_source_changed:tr("The PR changed during review. Retry to review the current source.","レビュー中にPRが更新されました。最新のソースで再試行してください。"),
  github_rate_limited:tr("GitHub rate-limited this read. Wait before retrying; no result was saved.","GitHubの取得上限に達しました。時間をおいて再試行してください。結果は保存されていません。"),
  github_unavailable:tr("The public PR could not be read. Check the repository and PR number.","公開PRを取得できませんでした。リポジトリとPR番号を確認してください。"),
  repository_not_enabled:tr("Choose a configured public company repository.","接続済みの自社公開リポジトリを選択してください。"),
  sign_in_required:tr("Sign in to continue.","ログインしてください。"),ownership_not_verified:tr("The DNS proof was not found. Check the TXT record and retry after DNS propagation.","DNSの証明が見つかりません。TXTレコードと反映状況を確認して再試行してください。"),
  target_execution_not_enabled:tr("Execution is currently limited to approved company origins. This target remains saved.","現在の実行範囲は承認済みの自社オリジンです。この対象は保存されています。"),
  target_not_ready:tr("Verify control and resume the target before running.","所有確認と対象の再開後に実行してください。"),
  https_root_required:tr("Use an HTTPS root URL without credentials, port, query or fragment.","認証情報・ポート・クエリ・フラグメントを含まないHTTPSのルートURLを指定してください。"),
  stale_fix:tr("The target scope changed. Run a new review and generate a new proposal.","対象の範囲が変更されました。再検査して新しい修正案を作成してください。"),
  stale_finding:tr("The target scope changed. Run a new review first.","対象の範囲が変更されました。先に再検査してください。"),
  run_already_active:tr("This target already has an active run. Open Run history.","この対象は実行中です。実行履歴を確認してください。"),
  csrf_denied:tr("Your session changed. Refresh before trying again.","セッションが変更されました。再読み込みしてください。"),
  daily_run_limit:tr("The pilot limit is 20 runs per account per day.","パイロットの上限は1アカウントあたり1日20回です。"),
  target_limit:tr("The pilot limit is 20 targets per workspace.","パイロットの上限はワークスペースあたり20対象です。"),
  unqualified_destination:tr("This network destination is not enabled for the current pilot.","このネットワーク宛先は現在のパイロットで実行できません。"),
  finding_changed:tr("This finding was updated. Refresh and review the current version.","この検出結果は更新されています。最新の状態を確認してください。"),
  fix_state_changed:tr("The proposal state changed. Refresh before reviewing.","修正案の状態が変更されています。再読み込みしてください。")
 };
 const message=e=>errors[e.code]||tr("The operation could not be completed. Refresh and retry. Code: ","操作を完了できませんでした。状態を確認して再試行してください。コード：")+e.code;
 async function call(path,body){
  const write=body!==undefined,r=await fetch("/api/"+path,{method:write?"POST":"GET",credentials:"same-origin",cache:"no-store",headers:write?{"content-type":"application/json","x-csrf-token":session?.csrf||""}:{},body:write?JSON.stringify(body):undefined});
  let data;try{data=await r.json();}catch{throw {code:"invalid_response"};}
  if(!r.ok){if(r.status===401){epoch++;session=null;state=null;login();}throw {code:data.error?.code||"request_failed"};}
  const scope=r.headers.get("x-mithril-scope");
  if(path==="session"){if(!scope||scope!==data.scope)throw {code:"session_changed"};}
  else if(session&&scope!==session.scope){epoch++;session=null;state=null;login();throw {code:"session_changed"};}
  return data;
 }
 function error(e){const el=$("#action-error");if(el){el.hidden=false;el.textContent=message(e);el.focus();}}
 function flash(text){const el=$("#action-notice");if(el){el.hidden=false;el.textContent=text;}}
 function login(){
  root.removeAttribute("aria-busy");root.innerHTML='<h1>'+tr("Sign in to Mithril CS","Mithril CSへログイン")+'</h1><p class="muted">'+tr("Use your existing Mithril account. Your targets and results stay private.","既存のMithrilアカウントを使用します。対象と結果は非公開です。")+'</p><button class="primary" id="sign-in">'+tr("Sign in","ログイン")+'</button><p id="login-status" role="status"></p>';
  $("#sign-in").onclick=()=>{const popup=window.open("https://auth.mithril.fund/sign-in","mithril-cs-sign-in","popup,width=600,height=760");
   $("#login-status").textContent=tr("Complete sign-in in the Mithril window, then return here.","Mithrilのウィンドウでログインを完了し、こちらへ戻ってください。");
   if(!popup)$("#login-status").innerHTML=tr('Your browser blocked the window. <a href="https://auth.mithril.fund/sign-in" target="_blank" rel="noopener">Open sign in</a>, then return here.','ウィンドウがブロックされました。<a href="https://auth.mithril.fund/sign-in" target="_blank" rel="noopener">ログイン画面を開き</a>、完了後に戻ってください。');
   let tries=0;const check=setInterval(async()=>{if(++tries>120){clearInterval(check);return;}try{const s=await call("session");session=s;clearInterval(check);if(popup&&!popup.closed)popup.close();await load();}catch{}},3000);
  };
 }
 async function load(){
  if(busy)return;busy=true;const version=++epoch;
  try{
   const s=await call("session");if(version!==epoch)return;session=s;
   const values=await Promise.all(["targets","runs","findings","fixes","reviews","infrastructure"].map(x=>call(x)));
   if(version!==epoch)return;state={targets:values[0].targets,runs:values[1].runs,findings:values[2].findings,fixes:values[3].fixes,reviews:values[4].reviews,infrastructure:values[5]};
   render();
  }catch(e){if(version!==epoch)return;if(e.code==="sign_in_required")login();else{root.removeAttribute("aria-busy");root.innerHTML='<h1>'+esc(names[tab]||names.targets)+'</h1><p class="error" role="alert">'+esc(message(e))+'</p><button id="retry-load">'+tr("Retry","再試行")+"</button>";$("#retry-load").onclick=load;}}
  finally{busy=false;}
 }
 const targetName=id=>state.targets.find(t=>t.id===id)?.label||id;
 function render(){
  root.setAttribute("aria-busy","false");
  const intro=tab==="targets"?tr("Register an HTTPS root URL, verify control and explicitly authorize each passive check.","HTTPSのルートURLを登録し、所有確認と実行ごとの承認を行います。"):
   tab==="runs"?tr("Source-bound receipts, received responses and incomplete coverage. Latest 100 runs.","ソースに紐づく記録、取得応答、未検査範囲。最新100実行を表示します。"):
   tab==="findings"?tr("Review candidates in context. Acknowledgement does not confirm an exploitable vulnerability. Latest 200 observations.","文脈と根拠を確認してください。確認済みの操作は、悪用可能性の証明ではありません。最新200観測を表示します。"):
   tr("Generate, review and export evidence-bound header configurations, then retest. Export does not deploy a change.","根拠に紐づくヘッダー設定を生成・確認・出力し、再検査します。出力では本番設定は変更されません。");
  root.innerHTML='<div class="row"><div><h1>'+esc(names[tab]||names.targets)+'</h1>'+(['targets','runs'].includes(tab)?'<p class="muted">'+intro+'</p>':'')+'</div><div class="actions"><button id="refresh">'+tr("Refresh","更新")+'</button><button id="sign-out">'+tr("Sign out","ログアウト")+'</button></div></div><p class="muted">'+tr("Personal workspace · single-URL passive review","個人ワークスペース・単一URLの受動的検査")+'</p><p id="action-error" class="error" role="alert" tabindex="-1" hidden></p><p id="action-notice" class="notice" role="status" hidden></p><div id="records"></div>';
  $("#refresh").onclick=load;$("#sign-out").onclick=async()=>{try{await call("logout",{});epoch++;session=null;state=null;login();}catch(e){error(e);}};
  const records=$("#records");
  if(["pentesting","reviews","fixes","coverage","infrastructure","reports","risk","findings"].includes(tab)){records.innerHTML=renderTask({tab,state,session,selection,tr,date});bindTasks();return;}
  if(tab==="targets"){
   records.innerHTML='<details id="add-target" '+(!state.targets.length?"open":"")+'><summary>'+tr("Add target","検査対象を追加")+'</summary><form id="target-form" class="editor"><label>'+tr("Name","名前")+'<input name="label" maxlength="100" required autocomplete="off"></label><label>'+tr("HTTPS root URL","HTTPSルートURL")+'<input name="url" type="url" placeholder="https://example.com/" required autocomplete="url"></label><label class="check"><input name="authorized" type="checkbox" required>'+tr("I own this target or have written authority to register it. Registration does not start a test.","この対象を所有している、または登録する書面の権限があります。登録だけでは検査は開始されません。")+'</label><button class="primary" type="submit">'+tr("Save target","対象を保存")+'</button></form></details><p class="notice">'+tr("Pilot execution: approved Mithril company origins only; one GET of the root URL, 15 seconds, 1 MiB. Other origins can be saved for onboarding.","パイロットの実行範囲：承認されたMithril自社オリジンのみ。ルートURLへのGET 1回、15秒・1MiB上限。他のオリジンは登録できます。")+'</p>'+
   state.targets.map(t=>'<article class="record" data-target="'+t.id+'"><div class="row"><div><h2>'+esc(t.label)+'</h2><p>'+esc(t.url)+'</p></div>'+badge(t.paused?"Paused":t.verifiedAt?"Verified":"Unverified")+'</div><details '+(!t.verifiedAt?"open":"")+'><summary>'+tr("Ownership verification","所有確認")+'</summary><p>'+tr("Add this DNS TXT record to the target domain, then verify.","対象ドメインに次のDNS TXTレコードを追加し、所有確認を実行してください。")+'</p><pre>'+esc(t.verification.name)+"\n"+esc(t.verification.value)+'</pre><button data-action="verify">'+tr("Verify control","所有確認を実行")+'</button></details><form class="run-form editor"><label class="check"><input name="authorized" type="checkbox" required>'+tr("I authorize one passive GET of this URL within the stated limits.","このURLへの受動的なGET 1回を、表示された上限内で許可します。")+'</label><div class="actions"><button class="primary" type="submit" '+(!t.verifiedAt||t.paused?"disabled":"")+'>'+tr("Run passive check","受動的検査を実行")+'</button><button type="button" data-action="pause">'+(t.paused?tr("Resume target","対象を再開"):tr("Pause target","対象を停止"))+'</button></div></form></article>').join("");
   $("#target-form").onsubmit=async event=>{event.preventDefault();const form=event.currentTarget,button=$("button",form);button.disabled=true;
    try{await call("targets",{label:form.elements.label.value,url:form.elements.url.value,authorized:form.elements.authorized.checked});await reloadAndNotice(tr("Target saved. Verify control before running.","保存しました。実行前に所有確認してください。"));}catch(e){error(e);button.disabled=false;}};
   root.querySelectorAll("[data-target]").forEach(record=>{const t=state.targets.find(x=>x.id===record.dataset.target);
    $('[data-action="verify"]',record).onclick=()=>action(()=>call("targets/"+t.id+"/verify",{}),tr("Control verified.","所有確認が完了しました。"));
    $('[data-action="pause"]',record).onclick=()=>action(()=>call("targets/"+t.id+"/pause",{paused:!t.paused}),tr("Target state updated. Previous run records are retained.","対象の状態を更新しました。過去の実行記録は保持しています。"));
    $(".run-form",record).onsubmit=event=>{event.preventDefault();startRun(t.id,event.currentTarget.elements.authorized.checked);};
   });
  }else if(tab==="runs"){
   records.innerHTML=state.runs.length?state.runs.map(r=>'<article class="record" data-run="'+r.id+'"><div class="row"><h2>'+esc(targetName(r.target_id))+'</h2>'+badge(r.status)+'</div><p class="muted">'+esc(date(r.created_at))+' · '+esc(r.id)+'</p>'+(r.report?'<p>'+tr("HTTP status: ","HTTPステータス：")+esc(r.report.httpStatus)+' · '+tr("Observed bytes: ","取得バイト数：")+esc(r.report.bytes)+' · '+tr("Body complete: ","本文取得：")+esc(r.report.bodyComplete?tr("Yes","完了"):tr("No","未完了"))+'</p><p class="notice">'+esc(r.report.limitations.join(" "))+'</p><details><summary>'+tr("Evidence receipt","根拠の記録")+'</summary><pre>'+esc(JSON.stringify({source:r.report.source,engine:r.report.engine,evidenceSha256:r.evidence_sha256,bodyPrefixSha256:r.report.bodyPrefixSha256,headersSha256:r.report.headersSha256,coverage:r.report.coverage},null,2))+'</pre></details>':"")+(r.error?'<p class="error">'+esc(r.error)+'</p>':"")+(["queued","running"].includes(r.status)?'<div class="actions"><button data-action="cancel">'+tr("Cancel run","実行を中止")+'</button>'+(r.expires_at<Date.now()?'<button data-action="reconcile">'+tr("Reconcile unknown outcome","不明な結果を照合")+'</button>':"")+"</div>":"")+'</article>').join(""):'<p class="empty">'+tr("No runs yet. Start a check from Targets.","実行履歴はまだありません。検査対象から検査を開始してください。")+'</p>';
   root.querySelectorAll("[data-run]").forEach(record=>record.querySelectorAll("[data-action]").forEach(button=>{button.onclick=()=>action(()=>call("runs/"+record.dataset.run+"/"+button.dataset.action,{}),tr("Run state updated.","実行状態を更新しました。"));}));
  }else if(tab==="findings"){
   records.innerHTML=state.findings.length?state.findings.map(f=>'<article class="record" data-finding="'+f.id+'"><div class="row"><h2>'+esc(f.data.title)+'</h2>'+badge(f.triage)+'</div><p class="muted">'+esc(targetName(f.target_id))+' · '+esc(f.rule_id)+' · '+esc(date(f.created_at))+'</p><p>'+esc(f.data.evidence)+'</p><details><summary>'+tr("Review and next action","確認と次のアクション")+'</summary><form class="triage-form editor"><label>'+tr("Disposition","判定")+'<select name="status">'+["needs-review","acknowledged","dismissed"].map(s=>'<option value="'+s+'" '+(s===f.triage?"selected":"")+'>'+esc(statusNames[s])+'</option>').join("")+'</select></label><label>'+tr("Review note","確認メモ")+'<textarea name="note" required minlength="3" maxlength="1000">'+esc(f.note||"")+'</textarea></label><button type="submit">'+tr("Save review","確認結果を保存")+'</button></form><button data-action="propose">'+tr("Generate fix proposal","修正案を生成")+'</button><p class="muted">'+tr("Header configuration requires compatibility review. No deployment starts here.","ヘッダー設定は互換性の確認が必要です。この操作ではデプロイされません。")+'</p></details></article>').join(""):'<p class="empty">'+tr("No recorded candidates. Check run coverage before drawing conclusions.","候補の記録はありません。判断する前に実行の検査範囲を確認してください。")+'</p>';
   root.querySelectorAll("[data-finding]").forEach(record=>{const f=state.findings.find(x=>x.id===record.dataset.finding);
    $(".triage-form",record).onsubmit=event=>{event.preventDefault();const form=event.currentTarget;action(()=>call("findings/"+f.id+"/triage",{status:form.elements.status.value,note:form.elements.note.value,version:f.version}),tr("Review saved.","確認結果を保存しました。"));};
    $('[data-action="propose"]',record).onclick=()=>action(()=>call("fixes",{findingId:f.id}),tr("Proposal saved. Review it in Auto-Fix.","修正案を保存しました。Auto-Fixで差分を確認してください。"));
   });
  }else if(tab==="fixes"){
   records.innerHTML='<p class="notice">'+tr("Review, configuration export and retesting are available. GitHub pull-request publication and automatic deployment are not connected.","レビュー・設定出力・再検査を利用できます。GitHubへのPR作成と自動デプロイは未接続です。")+'</p>'+
    (state.fixes.length?state.fixes.map(f=>'<article class="record" data-fix="'+f.id+'"><div class="row"><h2>'+esc(targetName(f.target_id))+'</h2>'+badge(f.status)+'</div><p class="muted">'+esc(date(f.created_at))+' · '+esc(f.id)+'</p><details open><summary>'+tr("Proposed configuration and evidence","提案する設定と根拠")+'</summary><pre>'+esc(f.patch)+'</pre></details><p class="muted">'+tr("Evidence SHA-256: ","根拠 SHA-256：")+esc(f.evidence_sha256)+'</p>'+
    (["proposed","approved"].includes(f.status)?'<form class="review-form editor"><label>'+tr("Review note","レビューのメモ")+'<textarea name="note" required minlength="3" maxlength="1000">'+esc(f.note||"")+'</textarea></label><label class="check"><input name="reviewed" type="checkbox" required>'+tr("I reviewed the evidence, target and configuration compatibility. This approval does not apply the change.","根拠・対象・設定の互換性を確認しました。この承認では設定は適用されません。")+'</label><div class="actions">'+(f.status==="proposed"?'<button name="decision" value="approve" type="submit">'+tr("Approve proposal","修正案を承認")+'</button>':"")+'<button name="decision" value="reject" type="submit">'+tr("Reject proposal","修正案を却下")+'</button></div></form>':"")+
    (["approved","exported"].includes(f.status)?'<button data-action="export">'+tr("Download approved configuration","承認済み設定をダウンロード")+'</button>':"")+
    '<form class="retest-form editor"><label class="check"><input name="authorized" type="checkbox" required>'+tr("I authorize another passive GET to retest this target.","再検査のため、この対象への受動的なGETを再度許可します。")+'</label><button type="submit">'+tr("Retest target","対象を再検査")+'</button></form></article>').join(""):'<p class="empty">'+tr("No proposals yet. Generate one from a supported finding.","修正案はまだありません。対応する検出結果から生成してください。")+'</p>');
   root.querySelectorAll("[data-fix]").forEach(record=>{const f=state.fixes.find(x=>x.id===record.dataset.fix),form=$(".review-form",record);
    if(form)form.onsubmit=event=>{event.preventDefault();const decision=event.submitter?.value;action(()=>call("fixes/"+f.id+"/"+decision,{note:form.elements.note.value,reviewed:form.elements.reviewed.checked}),tr("Proposal review saved.","修正案のレビューを保存しました。"));};
    const exportButton=$('[data-action="export"]',record);if(exportButton)exportButton.onclick=async()=>{try{const result=await call("fixes/"+f.id+"/export",{}),url=URL.createObjectURL(new Blob([result.patch],{type:"application/json"})),link=document.createElement("a");link.href=url;link.download=result.filename;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);await reloadAndNotice(tr("Configuration exported. Apply it in your deployment workflow, then retest.","設定を出力しました。ご自身のデプロイ手順で適用後、再検査してください。"));}catch(e){error(e);}};
    $(".retest-form",record).onsubmit=event=>{event.preventDefault();startRun(f.target_id,event.currentTarget.elements.authorized.checked);};
   });
  }
 }

 function download(value,filename){const url=URL.createObjectURL(new Blob([typeof value==='string'?value:JSON.stringify(value,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
 function bindTasks(){
  root.querySelectorAll('[data-select]').forEach(el=>el.onchange=()=>{selection[el.dataset.select]=el.value;delete selection.file;render();});
  root.querySelectorAll('[data-file]').forEach(el=>el.onclick=()=>{selection.file=el.dataset.file;render();});
  root.querySelectorAll('[data-select-finding]').forEach(el=>el.onclick=()=>{selection.finding=el.dataset.selectFinding;render();});
  root.querySelectorAll('[data-coverage-run]').forEach(el=>el.onclick=()=>location.assign('/app/reports?lang='+encodeURIComponent(document.documentElement.lang)+'&run='+encodeURIComponent(el.dataset.coverageRun)));
  root.querySelectorAll('[data-cancel-run]').forEach(el=>el.onclick=()=>action(()=>call('runs/'+el.dataset.cancelRun+'/cancel',{}),tr('Run cancelled.','実行を中止しました。')));
  const pr=$('#pr-form');if(pr)pr.onsubmit=event=>{event.preventDefault();action(async()=>{const r=await call('reviews',{repository:pr.elements.repository.value,number:Number(pr.elements.number.value),authorized:pr.elements.authorized.checked});selection.review=r.id;},tr('PR review saved. Inspect source and partial coverage.','PRレビューを保存しました。ソースと検査範囲を確認してください。'));};
  const triage=$('#task-triage');if(triage)triage.onsubmit=event=>{event.preventDefault();const f=state.findings.find(f=>f.id===triage.dataset.finding);action(()=>call('findings/'+f.id+'/triage',{status:triage.elements.status.value,note:triage.elements.note.value,version:f.version}),tr('Review saved.','確認結果を保存しました。'));};
  const propose=$('#task-propose');if(propose)propose.onclick=()=>action(async()=>{const r=await call('fixes',{findingId:propose.dataset.finding});selection.fix=r.id;},tr('Proposal saved. Open Auto-Fix to review.','修正案を保存しました。Auto-Fixで確認してください。'));
  root.querySelectorAll('.task-review-form').forEach(form=>form.onsubmit=event=>{event.preventDefault();const decision=event.submitter?.value;if(!['approve','reject'].includes(decision))return;action(()=>call('fixes/'+form.dataset.fix+'/'+decision,{note:form.elements.note.value,reviewed:form.elements.reviewed.checked}),tr('Proposal review saved.','修正案のレビューを保存しました。'));});
  root.querySelectorAll('.task-retest').forEach(form=>form.onsubmit=event=>{event.preventDefault();startRun(form.dataset.target,form.elements.authorized.checked);});
  root.querySelectorAll('[data-export-fix]').forEach(button=>button.onclick=()=>action(async()=>{const r=await call('fixes/'+button.dataset.exportFix+'/export',{});download(r.patch,r.filename);},tr('Configuration exported; no change was applied.','設定を出力しました。変更は適用されていません。')));
  const report=$('#export-report');if(report)report.onclick=()=>{const run=state.runs.find(r=>r.id===selection.run)||state.runs[0];if(!run)return;download({schemaVersion:1,exportedAt:new Date().toISOString(),source:run.report?.source,run,findings:state.findings.filter(f=>f.run_id===run.id),fixes:state.fixes.filter(f=>f.run_id===run.id),scope:'recorded partial passive review'},'mithril-report-'+run.id+'.json');flash(tr('Report exported.','レポートを出力しました。'));};
 }

 async function reloadAndNotice(text){await load();flash(text);}
 async function action(fn,text){if(root.dataset.mutating==="true")return;root.dataset.mutating="true";root.querySelectorAll("button").forEach(b=>b.disabled=true);
  try{await fn();await reloadAndNotice(text);}catch(e){await load();error(e);}finally{delete root.dataset.mutating;}}
 async function startRun(targetId,authorized){await action(()=>call("runs",{targetId,operation:crypto.randomUUID(),authorized}),tr("Run requested. Open Run history for status and coverage.","実行を依頼しました。実行履歴で状態と検査範囲を確認できます。"));}
 load();timer=setInterval(()=>{if(state?.runs.some(r=>["queued","running"].includes(r.status))&&root.dataset.mutating!=="true"&&["runs","pentesting","coverage"].includes(tab))load();},3000);
 window.addEventListener("focus",()=>{if(root.dataset.mutating!=="true"&&!document.activeElement?.closest("form"))load();});
 window.addEventListener("pageshow",e=>{if(e.persisted)load();});
 window.addEventListener("pagehide",()=>{epoch++;clearInterval(timer);session=null;state=null;root.replaceChildren();});
}
`;

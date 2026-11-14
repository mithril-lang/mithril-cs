// Credential-free, explicitly requested review of configured public company repositories.
// No target code execution, GitHub writes, installation grants or automatic triggers.
export async function reviewPullRequest({repository,number,allowed,read,reviewText,sha}) {
 if(!allowed.includes(repository)||!/^mithril-lang\/[a-zA-Z0-9_.-]+$/.test(repository)||!Number.isSafeInteger(number)||number<1||number>1000000)throw new Error('repository_not_enabled');
 const base='https://api.github.com/repos/'+repository+'/pulls/'+number;
 const pr=await read(base);
 if(pr.base?.repo?.full_name!==repository||!/^([a-f0-9]{40})$/.test(pr.head?.sha||'')||!/^([a-f0-9]{40})$/.test(pr.base?.sha||''))throw new Error('github_source_invalid');
 const rows=await read(base+'/files?per_page=100');
 if(!Array.isArray(rows)||rows.length>100||!Number.isSafeInteger(pr.changed_files)||pr.changed_files<rows.length)throw new Error('github_source_invalid');
 let patchBytes=0;
 const files=rows.map(f=>{
  if(typeof f.filename!=='string'||f.filename.length>512||typeof f.status!=='string')throw new Error('github_source_invalid');
  const patch=typeof f.patch==='string'?f.patch:'';
  patchBytes+=new TextEncoder().encode(patch).length;
  if(patchBytes>524288)throw new Error('github_patch_limit');
  // Preserve unified-diff line numbers, while reviewing added lines only.
  const added=patch.split('\n').map(l=>l.startsWith('+')&&!l.startsWith('+++')?l.slice(1):'').join('\n');
  return {path:f.filename,status:f.status,additions:f.additions,deletions:f.deletions,patch,
   findings:reviewText(added).map(x=>({...x,diffLine:x.line,validation:'not-validated',severity:'unrated'})),coverage:patch?'added-lines-lexical':'patch-unavailable'};
 });
 const current=await read(base);
 if(current.head?.sha!==pr.head.sha||current.base?.sha!==pr.base.sha||current.changed_files!==pr.changed_files)throw new Error('github_source_changed');
 const coverage={status:'partial',method:'added-lines-lexical',reviewedFiles:files.filter(f=>f.patch).length,receivedFiles:files.length,totalFiles:pr.changed_files,
  missingFiles:pr.changed_files-files.length,patchUnavailable:files.filter(f=>!f.patch).length,exploitValidation:false,ruleCount:4};
 return {repository,number,title:String(pr.title||'').slice(0,300),url:'https://github.com/'+repository+'/pull/'+number,
  head:pr.head.sha,base:pr.base.sha,files,coverage,sourceDigest:await sha(JSON.stringify(files)),githubWrites:false};
}

// Only the trusted owner publisher can write this fixed-prefix cache. It holds
// public source snapshots, never a GitHub token or a purported current-head result.
export function snapshotReader(snapshot,{repository,number,now}) {
 if(snapshot?.schemaVersion!==1||snapshot.public!==true||snapshot.repository!==repository||snapshot.number!==number||
    !Number.isSafeInteger(snapshot.observedAt)||now-snapshot.observedAt>1800000||snapshot.observedAt>now+5000||
    !Array.isArray(snapshot.files)||snapshot.pr?.base?.repo?.full_name!==repository||
    snapshot.head!==snapshot.pr?.head?.sha||snapshot.base!==snapshot.pr?.base?.sha)throw new Error('github_snapshot_unavailable');
 return async endpoint=>endpoint.endsWith('/files?per_page=100')?snapshot.files:snapshot.pr;
}

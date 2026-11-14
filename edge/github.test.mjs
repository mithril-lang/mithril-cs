import test from 'node:test';
import assert from 'node:assert/strict';
import {reviewPullRequest} from './github.mjs';
import engine from './engine.mjs';
import {sha} from './worker.mjs';
const repo='mithril-lang/mithril-cs',head='a'.repeat(40),base='b'.repeat(40);
function fixture(options={}){let reads=0;const urls=[];return {urls,input:{repository:repo,number:8,allowed:[repo],reviewText:engine.reviewText,sha,read:async url=>{urls.push(url);if(url.includes('/files?'))return [{filename:options.filename||'src/app.js',status:'modified',additions:1,deletions:0,patch:options.noPatch?undefined:'@@ -1 +1 @@\n+eval(userInput);'}];reads++;return {title:'Review',changed_files:options.total||1,base:{repo:{full_name:repo},sha:base},head:{sha:options.stale&&reads===2?'c'.repeat(40):head}};}}};}
test('public PR binds both source reads and reviews added lines using portable rules',async()=>{const f=fixture(),r=await reviewPullRequest(f.input);assert.equal(r.head,head);assert.equal(r.base,base);assert.equal(r.files[0].findings[0].rule,'MCS001');assert.equal(r.files[0].findings[0].diffLine,2);assert.equal(r.coverage.status,'partial');assert.equal(r.githubWrites,false);assert.equal(r.sourceDigest.length,64);assert.equal(f.urls.length,3);assert.ok(f.urls.every(u=>u.startsWith('https://api.github.com/repos/'+repo+'/pulls/8')));});
test('unauthorized repository never reaches the network',async()=>{const f=fixture();f.input.repository='foreign/repo';await assert.rejects(()=>reviewPullRequest(f.input),/repository_not_enabled/);assert.equal(f.urls.length,0);});
test('moving PR head fails without reusing stale findings',async()=>{const f=fixture({stale:true});await assert.rejects(()=>reviewPullRequest(f.input),/github_source_changed/);});
test('missing and omitted patches stay explicit; zero findings never implies complete',async()=>{const r=await reviewPullRequest(fixture({noPatch:true,total:101}).input);assert.equal(r.coverage.reviewedFiles,0);assert.equal(r.coverage.missingFiles,100);assert.equal(r.coverage.patchUnavailable,1);assert.equal(r.coverage.exploitValidation,false);});

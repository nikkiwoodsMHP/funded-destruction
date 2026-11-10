import assert from 'node:assert/strict';
import { test } from 'node:test';
import worker from '../src/worker.js';

const assets = {fetch: async()=>new Response('STATIC PREVIEW', {status:200})};
const env = { ASSETS: assets, INTAKE_ENABLED:'false' };
const call = (path, options={}, override=env) => worker.fetch(new Request('https://preview.example.test'+path,options),override);
const data = async r => r.json();

test('health is public and reports missing D1 connection',async()=>{
 const r=await call('/api/health');assert.equal(r.status,200);
 const j=await data(r);assert.equal(j.database_connected,false);assert.equal(j.intake_enabled,false);
 assert.equal(r.headers.get('cache-control'),'no-store');
});
test('public intake defaults off',async()=>{
 const r=await call('/api/config');assert.equal(r.status,200);
 assert.equal((await data(r)).intake_enabled,false);
});
test('company queries fail closed without D1',async()=>{
 const r=await call('/api/companies');assert.equal(r.status,503);
 assert.equal((await data(r)).error,'Database not configured');
});
test('report POST fails closed without D1',async()=>{
 const r=await call('/api/reports',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
 assert.equal(r.status,503);
});
test('private editor is inaccessible without valid Access identity',async()=>{
 const r=await call('/editor/');assert.equal(r.status,401);
 assert.match(await r.text(),/Cloudflare Access/);
});
test('static assets remain available',async()=>{
 const r=await call('/follow-the-money/');assert.equal(r.status,200);
 assert.equal(await r.text(),'STATIC PREVIEW');
});
test('public profile contains only approved records with approved sources',async()=>{
 const observed=[];
 const db={
  prepare(sql){
   observed.push(sql);
   return {all: async()=>({results: [{name:'companies'},{name:'sources'},{name:'financial_records'},{name:'relationships'},{name:'evidence_reports'},{name:'editorial_audit'}]}),bind(...args){
    return {
      first:async()=>({id:1,slug:'example',name:'Example Company'}),
      all:async()=>({results:[]})
    };
   }};
  }
 };
 const r=await call('/api/companies/example',{}, {...env,FD_DB:db});
 assert.equal(r.status,200);
 const j=await data(r);
 assert.equal(j.approved_only,true);
 assert.deepEqual(j.records,[]);
 assert.deepEqual(j.relationships,[]);
 assert(observed.some(s=>s.includes("f.review_status='approved'")&&s.includes("s.status='approved'")));
 assert(observed.some(s=>s.includes("r.review_status='approved'")&&s.includes("s.status='approved'")));
});
test('editor API fails closed without Access credentials, even with a D1 binding',async()=>{
 const db={prepare:()=>{throw Error('Editor should not touch database before auth')}};
 const r=await call('/api/editor/reports',{}, {...env,FD_DB:db});
 assert.equal(r.status,401);
});

test('health distinguishes a ready D1 schema from a bound empty database', async()=>{
 const ready={prepare:()=>({all:async()=>({results:['companies','sources','financial_records','relationships','evidence_reports','editorial_audit'].map(name=>({name}))})})};
 const readyResponse=await call('/api/health',{}, {...env,FD_DB:ready});
 const readyData=await data(readyResponse);
 assert.equal(readyData.database_status,'ready');
 assert.equal(readyData.database_connected,true);
 const empty={prepare:()=>({all:async()=>({results:[]})})};
 const missingResponse=await call('/api/health',{}, {...env,FD_DB:empty});
 const missingData=await data(missingResponse);
 assert.equal(missingData.database_status,'schema_missing');
 assert.equal(missingData.database_connected,false);
});

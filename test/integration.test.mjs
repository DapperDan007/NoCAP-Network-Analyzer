import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { request } from 'node:http';
import { fixture } from '../scripts/make-fixture.mjs';
import { analyzeCapture } from '../src/analyzer.mjs';

const tsharkAvailable = spawnSync(process.env.TSHARK_PATH || 'tshark',['--version'],{windowsHide:true}).status === 0;
test('real TShark extracts DNS and detects synthetic scan / polling',{skip:!tsharkAvailable},async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),'no-cap-parser-'));
  try{
    const capture=path.join(dir,'sample.pcap');await writeFile(capture,fixture());
    const report=await analyzeCapture(capture,{indicators:[]});
    assert.equal(report.summary.packets,31);assert.equal(report.domains[0].name,'telemetry.example.test');
    assert.ok(report.findings.some(f=>f.title==='Possible network scanning'));
    assert.ok(report.findings.some(f=>f.title==='Periodic outbound connection attempts'));
    const limited=await analyzeCapture(capture,{indicators:[]},{maxPackets:10});
    assert.equal(limited.summary.packets,10);assert.match(limited.limitations[0],/only part/);
    const broken=path.join(dir,'bad.pcap');await writeFile(broken,Buffer.from('not a capture'));
    await assert.rejects(analyzeCapture(broken,{indicators:[]}),/rejected/);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('HTTP authentication, validation, session lifecycle and persistence',{timeout:30000},async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),'no-cap-http-'));
  const token='test-only-token'; const port=18000+Math.floor(Math.random()*10000);
  const base=`http://127.0.0.1:${port}`;
  const headers={Authorization:`Bearer ${token}`};
  let child, output='';
  function start(apiToken=token){child=spawn(process.execPath,[fileURLToPath(new URL('../src/server.mjs',import.meta.url))],{env:{...process.env,HOST:'127.0.0.1',PORT:String(port),DATA_DIR:dir,API_TOKEN:apiToken,REQUIRE_AUTH:'false'},stdio:'pipe',windowsHide:true});child.stdout.on('data',b=>{output+=b;});child.stderr.on('data',b=>{output+=b;});}
  async function ready(){for(let i=0;i<60;i++){try{if((await fetch(`${base}/health`)).ok)return;}catch{}await new Promise(r=>setTimeout(r,100));}throw new Error(`Server did not become ready: ${output}`);}
  async function stop(){if(child.exitCode!==null)return;await new Promise(resolve=>{child.once('exit',resolve);child.kill();});}
  try{
    start();await ready();
    assert.equal((await fetch(`${base}/api/jobs`)).status,401);
    const config=await fetch(`${base}/api/config`,{headers});assert.equal((await config.json()).indicators,0);
    assert.equal((await fetch(`${base}/api/indicators`,{method:'PUT',headers:{...headers,Origin:'https://elsewhere.test'},body:'{"indicators":[]}'})).status,403);
    assert.equal((await fetch(`${base}/api/indicators`,{method:'PUT',headers,body:JSON.stringify({indicators:[{type:'ip',value:'bad'}]})})).status,400);
    const uploadHeaders={...headers,'Content-Type':'application/octet-stream','X-Filename':'sample.pcap'};
    assert.equal((await fetch(`${base}/api/jobs`,{method:'POST',headers:uploadHeaders,body:Buffer.from('invalid capture')})).status,400);
    const upload=await fetch(`${base}/api/jobs`,{method:'POST',headers:uploadHeaders,body:fixture()});assert.equal(upload.status,202);
    const job=await upload.json();let state;
    for(let i=0;i<100;i++){state=await (await fetch(`${base}/api/jobs/${job.id}`,{headers})).json();if(['failed','complete'].includes(state.status))break;await new Promise(r=>setTimeout(r,100));}
    assert.equal(state.status,tsharkAvailable?'complete':'failed');
    if(tsharkAvailable){const report=await (await fetch(`${base}/api/jobs/${job.id}/report`,{headers})).json();assert.equal(report.summary.packets,31);}
    await stop();start();await ready();
    const jobs=await (await fetch(`${base}/api/jobs`,{headers})).json();assert.equal(jobs.length,1);
    const capture=await fetch(`${base}/api/jobs/${job.id}/capture`,{headers});assert.equal((await capture.arrayBuffer()).byteLength,fixture().length);
    assert.equal((await fetch(`${base}/api/jobs/${job.id}`,{method:'DELETE',headers})).status,200);
    assert.equal((await fetch(`${base}/api/jobs/${job.id}`,{headers})).status,404);
    await stop();start('');await ready();
    const reboundStatus=await new Promise((resolve,reject)=>{const req=request(`${base}/api/jobs`,{headers:{Host:'rebound.example'}},res=>{res.resume();resolve(res.statusCode);});req.on('error',reject);req.end();});
    assert.equal(reboundStatus,403);
    assert.equal((await fetch(`${base}/api/jobs`)).status,200);
  }finally{await stop();await rm(dir,{recursive:true,force:true});}
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { Analysis, addressScope } from '../src/analyzer.mjs';
import { validateIntel, indexIntel } from '../src/intel.mjs';

const p=(overrides={})=>({'frame.number':'1','frame.time_epoch':'100','frame.len':'60','ip.src':'192.168.1.20','ip.dst':'93.184.216.34','tcp.srcport':'40000','tcp.dstport':'443','tcp.flags.syn':'1','tcp.flags.ack':'0','_ws.col.Protocol':'TCP',...overrides});
test('indicator matching respects domain boundaries and preserves provenance',()=>{
  const intel=validateIntel({indicators:[{type:'domain',value:'Bad.Example.',source:'Test feed',updated:new Date().toISOString()}]});
  const index=indexIntel(intel);assert.ok(index.domain('sub.bad.example'));assert.equal(index.domain('notbad.example'),undefined);
  const a=new Analysis(intel);a.add(p({'dns.qry.name':'bad.example'}));
  const r=a.finish();assert.equal(r.findings[0].indicator.source,'Test feed');assert.deepEqual(r.findings[0].packets,[1]);assert.equal(r.intelligence.indicators,1);
});
test('empty feeds explicitly report reputation checks unavailable',()=>{
  const a=new Analysis();a.add(p());const r=a.finish();assert.match(r.intelligence.status,/Not checked/);assert.equal(r.findings.length,0);
});
test('rapid SYN port scanning produces a finding but ordinary packets do not',()=>{
  const a=new Analysis(),normal=new Analysis();
  for(let i=0;i<22;i++){
    const row=p({'frame.number':String(i+1),'frame.time_epoch':String(100+i),'tcp.dstport':String(1000+i)});
    a.add(row);normal.add({...row,'tcp.flags.syn':'0'});
  }
  assert.ok(a.finish().findings.some(f=>f.title==='Possible network scanning'));
  assert.equal(normal.finish().findings.length,0);
});
test('connections spread beyond the window do not trigger a scan',()=>{
  const a=new Analysis();for(let i=0;i<25;i++)a.add(p({'frame.time_epoch':String(100+i*70),'tcp.dstport':String(1000+i)}));
  assert.equal(a.finish().findings.length,0);
});
test('periodic connection attempts are informational and retransmissions excluded',()=>{
  const a=new Analysis(),retry=new Analysis();for(let i=0;i<8;i++){
    const row=p({'frame.number':String(i+1),'frame.time_epoch':String(100+i*10),'tcp.srcport':String(40000+i)});
    a.add(row);retry.add({...row,'tcp.analysis.retransmission':'1'});
  }
  const finding=a.finish().findings[0];assert.equal(finding.severity,'info');assert.match(finding.action,/not evidence of malware/);
  assert.equal(retry.finish().findings.length,0);
});
test('HTTP credential content never appears in reports',()=>{
  const a=new Analysis();a.add(p({'http.authorization':'Basic c2VjcmV0OmNyZWRlbnRpYWw='}));const r=a.finish();
  assert.match(r.findings[0].title,/Basic authorization/);assert.ok(!JSON.stringify(r).includes('c2VjcmV0'));
});
test('DNS failures are attributed to response recipient',()=>{
  const a=new Analysis();for(let i=0;i<20;i++)a.add(p({'ip.src':'192.168.1.1','ip.dst':'192.168.1.20','dns.flags.response':'1','dns.flags.rcode':'3','dns.qry.name':`x${i}.test`,'tcp.flags.syn':'0'}));
  assert.equal(a.finish().findings[0].device,'192.168.1.20');
});
test('scope distinguishes ULA, public IPv6, multicast, and RFC1918',()=>{
  assert.equal(addressScope('fd00::1'),'local');assert.equal(addressScope('2606:4700::1111'),'external');
  assert.equal(addressScope('ff02::1'),'special');assert.equal(addressScope('172.20.1.1'),'local');assert.equal(addressScope('172.40.1.1'),'external');
});
test('stale intelligence lowers confidence and malformed indicators fail',()=>{
  const a=new Analysis(validateIntel({indicators:[{type:'ip',value:'93.184.216.34',source:'Old feed',updated:'2020-01-01'}]}));a.add(p());
  assert.equal(a.finish().findings[0].confidence,'low');
  assert.throws(()=>validateIntel({indicators:[{type:'ip',value:'not an ip'}]}));
});

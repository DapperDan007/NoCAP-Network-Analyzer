import test from 'node:test';
import assert from 'node:assert/strict';
import { subnetFor, prepareMap, buildGraph, conversations } from '../public/map-model.js';

const flow=(src,dst,bytes,port='443')=>({src,dst,bytes,packets:2,transport:'TCP',sourcePort:'50000',destinationPort:port,firstPacket:1});
const report={hosts:[
  {ip:'192.168.1.10',scope:'local'},{ip:'192.168.1.20',scope:'local'},
  {ip:'10.1.2.3',scope:'local'},{ip:'8.8.8.8',scope:'external'},
  {ip:'224.0.0.251',scope:'special'}
],flows:[flow('192.168.1.10','8.8.8.8',100),flow('8.8.8.8','192.168.1.10',40,'50000'),
  flow('192.168.1.20','8.8.8.8',60),flow('192.168.1.10','192.168.1.20',30),
  flow('10.1.2.3','224.0.0.251',50)],findings:[{device:'192.168.1.10'}]};

test('private groups mask IPv4 correctly and normalize compressed IPv6 /64',()=>{
  assert.equal(subnetFor('192.168.31.250',20),'192.168.16.0/20');
  assert.equal(subnetFor('10.1.99.9',16),'10.1.0.0/16');
  assert.equal(subnetFor('172.31.12.5'),'172.31.12.0/24');
  for(const ip of ['172.32.0.1','8.8.8.8','100.64.0.1','192.168.256.1'])assert.equal(subnetFor(ip),null);
  assert.equal(subnetFor('fd12:3456:0:1::a'),'fd12:3456:0:1::/64');
  assert.equal(subnetFor('fd12:3456:0000:0001:0000:0000:0000:000b'),'fd12:3456:0:1::/64');
  assert.equal(subnetFor('fc00::123'),'fc00:0:0:0::/64');
  assert.equal(subnetFor('2606:4700::1111'),null);
});
test('collapsed map counts cross-group traffic once and retains internal traffic',()=>{
  const graph=buildGraph(prepareMap(report));
  assert.equal(graph.links.length,1);assert.equal(graph.links[0].bytes,200);assert.equal(graph.links[0].packets,6);
  const local=graph.nodes.find(n=>n.id==='subnet:192.168.1.0/24');
  assert.equal(local.visibleMembers.length,2);assert.equal(local.internalBytes,30);assert.equal(local.findings,1);
  assert.equal(graph.hiddenSpecialFlows,1);
});
test('expanding subnets exposes host relationships without changing traffic totals',()=>{
  const graph=buildGraph(prepareMap(report),{expanded:new Set(['subnet:192.168.1.0/24','external'])});
  assert.equal(graph.links.length,3);assert.equal(graph.links.reduce((s,l)=>s+l.bytes,0),230);
  const link=graph.links.find(l=>[l.source,l.target].includes('192.168.1.10')&&[l.source,l.target].includes('8.8.8.8'));
  assert.equal(link.bytes,140);assert.equal(link.forwardBytes+link.reverseBytes,140);
});
test('host focus reveals the host and limits links to its direct neighbors',()=>{
  const graph=buildGraph(prepareMap(report),{focus:'192.168.1.10'});
  assert.ok(graph.nodes.some(n=>n.id==='192.168.1.10'));
  assert.ok(!graph.nodes.some(n=>n.id==='subnet:10.1.2.0/24'));
  assert.equal(graph.links.reduce((sum,l)=>sum+l.bytes,0),170);
});
test('conversation inspector reports observed direction, ports, and internal traffic',()=>{
  const model=prepareMap(report),peers=conversations(model,'192.168.1.10');
  const external=peers.find(p=>p.peer==='8.8.8.8');
  assert.equal(external.sentBytes,100);assert.equal(external.receivedBytes,40);assert.equal(external.bytes,140);
  assert.deepEqual(external.ports,['TCP/443','TCP/50000']);
  const group=conversations(model,'subnet:192.168.1.0/24');
  assert.equal(group.find(p=>p.internal).bytes,30);
  assert.equal(group.find(p=>p.peer==='8.8.8.8').bytes,200);
});
test('display caps disclose omitted nodes and flows; empty captures work',()=>{
  const g=buildGraph(prepareMap(report),{expanded:new Set(['subnet:192.168.1.0/24','external']),limit:1});
  assert.equal(g.nodes.length,1);assert.ok(g.omittedNodes>0);assert.ok(g.omittedFlows>0);
  assert.equal(buildGraph(prepareMap({})).nodes.length,0);
});
test('special addresses are opt-in and findings decorate endpoints',()=>{
  const model=prepareMap(report),g=buildGraph(model,{includeSpecial:true});
  assert.ok(g.nodes.some(n=>n.id==='special'));assert.equal(g.hiddenSpecialFlows,0);
  assert.equal(model.hosts.get('192.168.1.10').findings,1);
});
test('intra-subnet conversation pairs combine reverse traffic once',()=>{
  const model=prepareMap({...report,flows:[flow('192.168.1.10','192.168.1.20',30),flow('192.168.1.20','192.168.1.10',10)]});
  const peers=conversations(model,'subnet:192.168.1.0/24');
  assert.equal(peers.length,1);assert.equal(peers[0].bytes,40);assert.equal(peers[0].packets,4);
});

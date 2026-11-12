import { prepareMap, buildGraph, conversations } from './map-model.js';

const $=s=>document.querySelector(s),svg=$('#network-svg'),ns='http://www.w3.org/2000/svg';
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const num=n=>Number(n||0).toLocaleString();
function bytes(n){let i=0;const units=['B','KB','MB','GB'];while(n>=1024&&i<3){n/=1024;i++;}return `${Number(n||0).toFixed(i?1:0)} ${units[i]}`;}
function el(name,attrs={},text){const node=document.createElementNS(ns,name);for(const [key,value]of Object.entries(attrs))node.setAttribute(key,value);if(text!==undefined)node.textContent=text;return node;}
let token=sessionStorage.getItem('no-cap-token')||sessionStorage.getItem('pcap-lens-token')||'',model,report,graph,selected=null,focus=null;
if(token){sessionStorage.setItem('no-cap-token',token);sessionStorage.removeItem('pcap-lens-token');}
let expanded=new Set(),positions=new Map(),nodeEls=new Map(),linkEls=[],halos=[];
let camera={x:0,y:0,k:1},gesture=null,lastClick=null,frame=0,sessionId=null,loadSequence=0;
function message(text){$('#map-message').hidden=!text;$('#map-message').textContent=text;}
async function api(route){const r=await fetch(route,{headers:token?{Authorization:`Bearer ${token}`}:{}});if(r.status===401){if(!$('#map-auth').open)$('#map-auth').showModal();throw new Error('Enter your server access token to open the map.');}if(!r.ok)throw new Error((await r.json()).error||'Request failed.');return r.json();}
function transform(){ $('#map-camera').setAttribute('transform',`translate(${camera.x},${camera.y}) scale(${camera.k})`);$('#map-scale').textContent=`${Math.round(camera.k*100)}%`; }
function zoom(factor,x=svg.clientWidth/2,y=svg.clientHeight/2){const k=Math.min(3.5,Math.max(.12,camera.k*factor)),ratio=k/camera.k;camera.x=x-(x-camera.x)*ratio;camera.y=y-(y-camera.y)*ratio;camera.k=k;transform();}
function fit(){
  if(!graph?.nodes.length)return;
  const ps=graph.nodes.map(n=>positions.get(n.id));
  const minX=Math.min(...ps.map(p=>p.x))-115,maxX=Math.max(...ps.map(p=>p.x))+115,minY=Math.min(...ps.map(p=>p.y))-65,maxY=Math.max(...ps.map(p=>p.y))+65;
  camera.k=Math.min(1.4,Math.max(.12,Math.min((svg.clientWidth-55)/(maxX-minX),(svg.clientHeight-110)/(maxY-minY))));
  camera.x=svg.clientWidth/2-(minX+maxX)/2*camera.k;camera.y=svg.clientHeight/2-(minY+maxY)/2*camera.k;transform();
}
function makePositions(){
  const groups=[...model.groups.values()].filter(g=>g.scope==='local').sort((a,b)=>a.id.localeCompare(b.id));
  for(const n of graph.nodes){
    if(positions.has(n.id))continue;
    const g=model.groups.get(n.kind==='group'?n.id:n.group);
    const local=g.scope==='local',index=local?groups.findIndex(a=>a.id===g.id):0;
    const cx=local?240:850,cy=local?140+index*210:g.scope==='special'?650:300;
    if(n.kind==='group'){positions.set(n.id,{x:cx,y:cy});continue;}
    const siblings=graph.nodes.filter(a=>a.kind==='host'&&a.group===n.group);
    const order=siblings.findIndex(a=>a.id===n.id),angle=order*2.39996;
    const radius=40+Math.sqrt(order)*42;
    positions.set(n.id,{x:cx+Math.cos(angle)*radius,y:cy+Math.sin(angle)*radius});
  }
}
function paint(){
  if(!graph)return;
  for(const n of graph.nodes){const p=positions.get(n.id);nodeEls.get(n.id).setAttribute('transform',`translate(${p.x},${p.y})`);}
  for(const [link,node]of linkEls){const a=positions.get(link.source),b=positions.get(link.target);node.setAttribute('x1',a.x);node.setAttribute('y1',a.y);node.setAttribute('x2',b.x);node.setAttribute('y2',b.y);}
  for(const halo of halos){const ps=halo.ids.map(id=>positions.get(id));const x=Math.min(...ps.map(p=>p.x))-65,y=Math.min(...ps.map(p=>p.y))-54,w=Math.max(...ps.map(p=>p.x))-x+65,h=Math.max(...ps.map(p=>p.y))-y+54;halo.rect.setAttribute('x',x);halo.rect.setAttribute('y',y);halo.rect.setAttribute('width',w);halo.rect.setAttribute('height',h);halo.text.setAttribute('x',x+12);halo.text.setAttribute('y',y+17);}
}
function settle(){
  cancelAnimationFrame(frame);let ticks=0;
  const step=()=>{
    if(gesture){frame=requestAnimationFrame(step);return;}
    const nodes=graph.nodes;
    for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
      const a=positions.get(nodes[i].id),b=positions.get(nodes[j].id);let dx=b.x-a.x,dy=b.y-a.y;if(dx===0&&dy===0){dx=1;dy=1;}
      const minimum=nodes[i].kind==='group'||nodes[j].kind==='group'?190:110;
      const dist=Math.hypot(dx,dy);if(dist>=minimum)continue;
      const move=(minimum-dist)*.065;dx=dx/dist*move;dy=dy/dist*move;
      if(!a.pinned){a.x-=dx;a.y-=dy;}if(!b.pinned){b.x+=dx;b.y+=dy;}
    }
    paint();if(++ticks<65)frame=requestAnimationFrame(step);
  };step();
}
function groupList(){
  const panel=$('#map-groups');panel.replaceChildren();
  for(const g of [...model.groups.values()].sort((a,b)=>a.scope==='local'&&b.scope!=='local'?-1:b.scope==='local'&&a.scope!=='local'?1:b.weight-a.weight)){
    if(g.scope==='special'&&!$('#map-special').checked)continue;
    const item=document.createElement('div');item.className='map-group';
    item.innerHTML=`<button class="group-select">${esc(g.label)}</button><small>${num(g.members.length)} endpoints · ${bytes(g.weight)}</small><button class="group-toggle">${expanded.has(g.id)?'− Collapse group':'+ Expand group'}</button>`;
    item.querySelector('.group-select').onclick=()=>select(g.id);
    item.querySelector('.group-toggle').onclick=()=>toggle(g.id);
    panel.append(item);
  }
}
function toggle(id){expanded.has(id)?expanded.delete(id):expanded.add(id);draw(true);select(id);}
function draw(refit=false){
  if(!model)return;
  cancelAnimationFrame(frame);
  graph=buildGraph(model,{expanded,focus,includeSpecial:$('#map-special').checked});makePositions();
  $('#map-halos').replaceChildren();$('#map-links').replaceChildren();$('#map-nodes').replaceChildren();nodeEls=new Map();linkEls=[];halos=[];
  for(const g of model.groups.values()){
    if(!expanded.has(g.id)||g.scope!=='local')continue;
    const ids=graph.nodes.filter(n=>n.group===g.id).map(n=>n.id);if(!ids.length)continue;
    const rect=el('rect',{class:'subnet-halo',rx:24}),text=el('text',{class:'subnet-halo-label'},g.label);
    $('#map-halos').append(rect,text);halos.push({rect,text,ids});
  }
  for(const link of graph.links){const line=el('line',{class:'network-link','stroke-width':Math.min(7,1+Math.log10(Math.max(1,link.bytes))/1.5),'vector-effect':'non-scaling-stroke'});line.append(el('title',{},`${link.source} ↔ ${link.target}\n${bytes(link.bytes)} · ${num(link.packets)} packets · ${link.protocols.join(', ')}`));$('#map-links').append(line);linkEls.push([link,line]);}
  for(const n of graph.nodes){
    const scope=n.kind==='group'?n.scope:model.groups.get(n.group).scope;
    const group=el('g',{class:`network-node ${scope}`,'data-id':n.id,tabindex:0,role:'button','aria-label':n.kind==='group'?`${n.label}, ${n.visibleMembers.length} endpoints. Double-click to expand.`:`Host ${n.ip}. Select to inspect connections.`});
    if(n.kind==='group'){
      group.append(el('rect',{x:-103,y:-34,width:206,height:68,rx:13}));
      group.append(el('text',{'text-anchor':'middle',y:-5},n.label.length>29?'External / other endpoints':n.label));
      group.append(el('text',{'text-anchor':'middle',y:13,class:'node-subtitle'},`${num(n.visibleMembers.length)} hosts · ${bytes(n.weight)}`));
      group.append(el('text',{'text-anchor':'middle',y:27,class:'node-subtitle'},'double-click to expand'));
    }else{
      const r=Math.min(24,12+Math.log10(Math.max(1,n.weight))*1.5);group.append(el('circle',{r}));
      group.append(el('text',{'text-anchor':'middle',y:r+18},n.ip));
      group.append(el('text',{'text-anchor':'middle',y:r+32,class:'node-subtitle'},bytes(n.weight)));
      if(n.findings)group.append(el('text',{x:r+5,y:-r+3,class:'node-alert'},`${n.findings} signal${n.findings===1?'':'s'}`));
    }
    group.append(el('title',{},`${n.label||n.ip}\n${bytes(n.weight)} observed frame bytes`));
    group.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();e.stopPropagation();if(e.key===' '&&n.kind==='group')toggle(n.id);else select(n.id);}});
    $('#map-nodes').append(group);nodeEls.set(n.id,group);
  }
  if(!graph.nodes.length)$('#map-nodes').append(el('text',{x:40,y:100,class:'map-no-data'},'No endpoints in this view. Try including special-use addresses or clearing focus.'));
  paint();if(refit)fit();settle();groupList();highlight();
  const notes=[`${num(graph.nodes.length)} nodes`,`${num(graph.links.length)} links`];
  if(graph.omittedNodes||graph.omittedLinks||graph.omittedFlows)notes.push(`Display limits: ${num(graph.omittedNodes)} nodes, ${num(graph.omittedLinks)} links and ${num(graph.omittedFlows)} directional flows omitted. Focus a group or host to narrow the view.`);
  if(graph.hiddenSpecialFlows)notes.push(`${num(graph.hiddenSpecialFlows)} special-use flows hidden`);
  if(focus)notes.push('Focused connections');
  $('#map-summary').textContent=notes.join(' · ');$('#map-clear-focus').hidden=!focus;
}
function highlight(){
  const neighbors=new Set([selected]);for(const l of graph?.links||[])if(l.source===selected||l.target===selected){neighbors.add(l.source);neighbors.add(l.target);}
  const visible=selected&&nodeEls.has(selected);
  for(const [id,node]of nodeEls){node.classList.toggle('selected',id===selected);node.classList.toggle('dim',!!visible&&!neighbors.has(id));}
  for(const [l,line]of linkEls){const related=l.source===selected||l.target===selected;line.classList.toggle('highlight',!!visible&&related);line.classList.toggle('dim',!!visible&&!related);}
}
function select(id){
  if(!model)return;selected=id;highlight();
  const node=model.groups.get(id)||model.hosts.get(id);if(!node)return;
  const group=node.kind==='group',peers=conversations(model,id),panel=$('#map-inspector');
  panel.innerHTML=`<div class="eyebrow">${group?'ADDRESS GROUP':'ENDPOINT'}</div><h2>${esc(node.label||node.ip)}</h2><p>${esc(group?`${num(node.members.length)} observed endpoints in this logical group.`:node.identity||'Observed IP endpoint')}</p><div class="inspector-metrics"><div><small>OBSERVED BYTES</small><strong>${bytes(node.weight)}</strong></div><div><small>FINDINGS</small><strong>${num(node.findings)}</strong></div></div><div class="actions">${group?`<button id="inspect-expand">${expanded.has(id)?'Collapse':'Expand'} group</button>`:''}<button id="inspect-focus">Focus connections</button></div>${!group&&node.macs?.length?`<p>Observed MAC: ${esc(node.macs.join(', '))}</p>`:''}${!group&&node.names?.length?`<div class="inspector-section">Contacted / queried names</div><p>${node.names.slice(0,12).map(esc).join('<br>')}</p>`:''}<div class="inspector-section">${group?'Conversations (including intra-group)':'Communicating peers'} · ${num(peers.length)}</div><div id="map-peers"></div>`;
  if(group)$('#inspect-expand').onclick=()=>toggle(id);
  $('#inspect-focus').onclick=()=>{focus=id;draw(true);select(id);};
  for(const peer of peers.slice(0,80)){
    const card=document.createElement('div');card.className='peer-card';
    const label=peer.internal?document.createElement('strong'):document.createElement('button');label.textContent=peer.peer;
    if(!peer.internal)label.onclick=()=>reveal(peer.peer);
    card.append(label);
    const info=document.createElement('p');info.innerHTML=`${bytes(peer.bytes)} · ${num(peer.packets)} packets<br>${peer.internal?'Within group':`Sent ${bytes(peer.sentBytes)} · received ${bytes(peer.receivedBytes)}`}<br>Observed destination ports: ${esc(peer.ports.slice(0,12).join(', ')||peer.protocols.join(', '))}<br><code>First packet #${num(peer.firstPacket)}</code>`;card.append(info);$('#map-peers').append(card);
  }
  if(peers.length>80){const notice=document.createElement('p');notice.textContent='Top 80 conversations shown. The full report remains available in Capture analysis.';$('#map-peers').append(notice);}
  if(!peers.length)$('#map-peers').innerHTML='<p>No conversations observed for this endpoint in this capture.</p>';
}
function reveal(id){
  const host=model.hosts.get(id);if(!host)return;
  if(host.group==='special')$('#map-special').checked=true;
  expanded.add(host.group);focus=id;draw(true);select(id);
}
svg.addEventListener('wheel',e=>{e.preventDefault();const r=svg.getBoundingClientRect();zoom(Math.exp(-e.deltaY*.0015),e.clientX-r.left,e.clientY-r.top);},{passive:false});
svg.addEventListener('pointerdown',e=>{
  if(e.button!==0||!graph)return;
  const node=e.target.closest('.network-node'),id=node?.getAttribute('data-id');
  gesture={pointer:e.pointerId,id,startX:e.clientX,startY:e.clientY,x:camera.x,y:camera.y,moved:false};
  if(id){const p=positions.get(id);gesture.nodeX=p.x;gesture.nodeY=p.y;p.pinned=true;}
  svg.setPointerCapture(e.pointerId);
});
svg.addEventListener('pointermove',e=>{
  if(!gesture||gesture.pointer!==e.pointerId)return;const dx=e.clientX-gesture.startX,dy=e.clientY-gesture.startY;
  if(Math.hypot(dx,dy)>4)gesture.moved=true;
  if(gesture.id){const p=positions.get(gesture.id);p.x=gesture.nodeX+dx/camera.k;p.y=gesture.nodeY+dy/camera.k;paint();}
  else{camera.x=gesture.x+dx;camera.y=gesture.y+dy;transform();}
});
function endGesture(e){
  if(!gesture||gesture.pointer!==e.pointerId)return;
  const g=gesture;gesture=null;if(svg.hasPointerCapture(e.pointerId))svg.releasePointerCapture(e.pointerId);
  if(e.type==='pointercancel'||g.moved||!g.id){lastClick=null;return;}
  // Pointer capture retargets native click/dblclick events to the SVG. Track the
  // original hit explicitly so dragging and double-click expansion coexist.
  const now=performance.now();
  if(lastClick?.id===g.id&&now-lastClick.time<450&&model.groups.has(g.id)){lastClick=null;toggle(g.id);}
  else{lastClick={id:g.id,time:now};select(g.id);}
}
svg.addEventListener('pointerup',endGesture);svg.addEventListener('pointercancel',endGesture);
svg.addEventListener('keydown',e=>{if(e.target!==svg)return;if(['+','=','-','Home','ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.key)){e.preventDefault();if(e.key==='Home')fit();else if(['+','=','-'].includes(e.key))zoom(e.key==='-'?.8:1.25);else{camera.x+=e.key==='ArrowLeft'?40:e.key==='ArrowRight'?-40:0;camera.y+=e.key==='ArrowUp'?40:e.key==='ArrowDown'?-40:0;transform();}}});
$('#map-zoom-in').onclick=()=>zoom(1.25);$('#map-zoom-out').onclick=()=>zoom(.8);$('#map-fit').onclick=fit;
$('#map-collapse').onclick=()=>{expanded.clear();focus=null;selected=null;draw(true);resetInspector();};
$('#map-clear-focus').onclick=()=>{focus=null;draw(true);if(selected)select(selected);};
$('#map-special').onchange=()=>draw(true);
$('#map-prefix').onchange=()=>{if(!report)return;model=prepareMap(report,Number($('#map-prefix').value));expanded.clear();positions.clear();focus=null;selected=null;draw(true);resetInspector();};
function resetInspector(){$('#map-inspector').innerHTML='<div class="eyebrow">CONNECTION INSPECTOR</div><h2>Choose an endpoint</h2><p>Select a group or host to inspect its communications. Double-click a group to expand it; drag the canvas to pan.</p>';}
$('#map-search').addEventListener('input',()=>{
  const query=$('#map-search').value.trim().toLowerCase(),results=$('#map-search-results');results.replaceChildren();results.hidden=!query||!model;
  if(!query||!model)return;
  const matches=[...model.hosts.values()].filter(h=>h.ip.toLowerCase().includes(query)||(h.names||[]).some(n=>n.toLowerCase().includes(query)));
  for(const h of matches.slice(0,16)){const button=document.createElement('button');button.textContent=h.ip;button.onclick=()=>{reveal(h.id);results.hidden=true;};results.append(button);}
  const label=document.createElement('span');label.className='muted';label.textContent=matches.length?`${num(matches.length)} matches${matches.length>16?' · first 16 shown':''}`:'No matching endpoints.';results.append(label);
});
async function load(id){
  const sequence=++loadSequence;message('');
  try{
    const result=await api(`/api/jobs/${id}/report`);if(sequence!==loadSequence)return;
    sessionId=id;report=result;model=prepareMap(report,Number($('#map-prefix').value));selected=null;focus=null;expanded.clear();positions.clear();$('#map-search').value='';$('#map-search-results').hidden=true;
    const url=new URL(location.href);url.searchParams.set('session',id);history.replaceState(null,'',url);$('#back-analysis').href=`/?session=${encodeURIComponent(id)}`;
    draw(true);resetInspector();
  }catch(e){if(sequence===loadSequence)message(e.message);}
}
$('#map-session').onchange=()=>load($('#map-session').value);
$('#map-connect').onclick=()=>{token=$('#map-token').value.trim();sessionStorage.setItem('no-cap-token',token);sessionStorage.removeItem('pcap-lens-token');$('#map-token').value='';setTimeout(init,0);};
async function init(){
  try{
    const jobs=(await api('/api/jobs')).filter(j=>j.status==='complete');$('#map-session').replaceChildren();
    if(!jobs.length){$('#map-session').append(new Option('No completed captures',''));message('Analyze a capture first, then open Network map. Your saved captures will appear here.');return;}
    for(const job of jobs)$('#map-session').append(new Option(job.filename,job.id));
    const wanted=new URL(location.href).searchParams.get('session');const id=jobs.some(j=>j.id===wanted)?wanted:jobs[0].id;$('#map-session').value=id;await load(id);
  }catch(e){message(e.message);}
}
new ResizeObserver(()=>{if(graph)fit();}).observe(svg);
await init();

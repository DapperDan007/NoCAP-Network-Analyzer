const $ = selector=>document.querySelector(selector);
// Preserve existing authenticated browser sessions across the No-CAP rename.
let token = sessionStorage.getItem('no-cap-token') || sessionStorage.getItem('pcap-lens-token') || '';
if (token) { sessionStorage.setItem('no-cap-token', token); sessionStorage.removeItem('pcap-lens-token'); }
let selected, report, tab='findings', poll, uploadBusy=false;
const number = n=>Number(n).toLocaleString();
function bytes(n) { const units=['B','KB','MB','GB']; let i=0; while(n>=1024 && i<3){n/=1024;i++;} return `${n.toFixed(i?1:0)} ${units[i]}`; }
const esc = value=>String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function message(text) { $('#message').textContent=text; $('#message').hidden=!text; }
async function api(url,options={}) {
  const response=await fetch(url,{...options,headers:{...options.headers,...(token?{Authorization:`Bearer ${token}`}:{})}});
  if(response.status===401) { $('#auth-dialog').showModal(); throw new Error('Access token required.'); }
  if(!response.ok){const body=await response.json().catch(()=>({}));throw new Error(body.error||`Request failed (${response.status})`);}
  return response;
}
async function config(){
  const c=await (await api('/api/config')).json();
  $('#upload-limit').textContent=`Up to ${bytes(c.maxUploadBytes)} · PCAP / PCAPNG · ${bytes(c.maxStorageBytes)} capture storage`;
  $('#intel-status').textContent=c.indicators?`${number(c.indicators)} local indicators · imported ${new Date(c.importedAt).toLocaleDateString()}`:'No indicators imported · reputation checks unavailable';
  return c;
}
async function sessions(){
  const jobs=await (await api('/api/jobs')).json();
  $('#sessions').replaceChildren();
  if(!jobs.length) $('#sessions').innerHTML='<p class="muted">No captures yet.</p>';
  for(const job of jobs){
    const button=document.createElement('button');button.className=`session ${selected===job.id?'selected':''}`;
    button.innerHTML=`<span>${esc(job.filename)}</span><small>${esc(job.status)} · ${new Date(job.createdAt).toLocaleDateString()}</small>`;
    button.addEventListener('click',()=>openJob(job.id).catch(e=>message(e.message)));$('#sessions').append(button);
  }
  return jobs;
}
async function openJob(id){
  clearTimeout(poll);selected=id;report=null;message('');$('#empty').hidden=true;$('#report').hidden=true;
  const job=await (await api(`/api/jobs/${id}`)).json();
  await sessions();
  $('#job-state').hidden=job.status==='complete';
  if(job.status==='complete'){
    report=await (await api(`/api/jobs/${id}/report`)).json();
    $('#nav-map').href=`/map?session=${encodeURIComponent(id)}`;
    $('#report').hidden=false;$('#report-title').textContent=job.filename;
    $('#report-meta').textContent=`${new Date(job.createdAt).toLocaleString()} · ${bytes(job.size)} capture · ${report.summary.duration.toFixed(1)}s observed`;
    $('#stats').innerHTML=[['Packets',number(report.summary.packets)],['Endpoints',number(report.summary.hosts)],['Connections',number(report.summary.flows)],['Findings',number(report.summary.findings)],['Frame bytes',bytes(report.summary.bytes)]].map(([label,value])=>`<div class="stat"><small>${label}</small><strong>${value}</strong></div>`).join('');
    render();
  }else{
    $('#job-state').innerHTML=`<div class="eyebrow">${esc(job.status.toUpperCase())}</div><h2>${esc(job.filename)}</h2><p>${esc(job.error || (job.status==='queued'?'Waiting for the current analysis to finish.':`Analyzing locally · ${number(job.processedPackets)} packets processed…`))}</p>`;
    if(job.status==='failed'){
      const button=document.createElement('button');button.textContent='Delete failed session';button.className='danger';button.onclick=()=>removeJob(id);$('#job-state').append(button);
    }else poll=setTimeout(()=>openJob(id).catch(e=>message(e.message)),2000);
  }
}
function table(headers,rows){return `<div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map(c=>`<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;}
function render(){
  if(!report)return;
  const query=$('#filter').value.toLowerCase();
  const descriptions={findings:'Prioritized signals with evidence. A finding is a lead, not a verdict.',hosts:'Observed IP endpoints. Scope reflects address ranges, not verified network ownership.',flows:'Directional transport flows, ranked by observed frame bytes.',domains:'Names visible in DNS, TLS, or HTTP. Counts are packet observations.',coverage:'What was checked, and what this capture cannot tell you.'};
  $('#tab-description').textContent=descriptions[tab];$('#filter').hidden=tab==='coverage';$('#row-limit').textContent='';
  document.querySelectorAll('[data-tab]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.tab===tab)));
  if(tab==='coverage'){
    $('#report-content').innerHTML=`<div class="notice"><strong>Threat intelligence: ${esc(report.intelligence.status)}</strong><p>${number(report.intelligence.indicators)} indicators available at analysis time. Importing a new feed affects future analyses; upload the capture again to reanalyze.</p><strong>Analysis scope</strong><ul>${report.limitations.map(s=>`<li>${esc(s)}</li>`).join('')}</ul>${report.parserWarning?`<strong>Parser warning</strong><p>${esc(report.parserWarning)}</p>`:''}<strong>Protocols observed</strong><p>${report.protocols.map(p=>`${esc(p.name)} (${number(p.packets)})`).join(' · ')}</p></div>`;return;
  }
  const rows=report[tab].filter(row=>JSON.stringify(row).toLowerCase().includes(query));
  const visible=rows.slice(0,300);if(rows.length>300)$('#row-limit').textContent=`Showing 300 of ${number(rows.length)} matches. Filter to narrow results or export the full JSON report.`;
  if(!rows.length){$('#report-content').innerHTML=`<div class="notice">${query?'No results match this filter.':tab==='findings'?'No findings from the enabled checks. This does not establish that the traffic or devices are safe.':'No observations in this view.'}</div>`;return;}
  if(tab==='findings')$('#report-content').innerHTML=visible.map(f=>`<article class="finding"><div class="finding-top"><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span><h3>${esc(f.title)}</h3><span class="confidence">${esc(f.confidence)} confidence</span></div><p>${esc(f.evidence)}</p><p class="finding-action">${esc(f.action)}</p><div class="evidence">Endpoint ${esc(f.device)} &nbsp; / &nbsp; ${number(f.count)} matching observations &nbsp; / &nbsp; Packet refs: ${f.packets.map(esc).join(', ')}</div></article>`).join('');
  if(tab==='hosts')$('#report-content').innerHTML=table(['Address / scope','Identity hypothesis','Sent / received','Observed MACs','Contacted names'],visible.map(h=>[`${h.ip} (${h.scope})`,h.identity,`${bytes(h.sentBytes)} / ${bytes(h.receivedBytes)}`,h.macs.join(', '),h.names.slice(0,8).join(', ')]));
  if(tab==='flows')$('#report-content').innerHTML=table(['Source','Destination','Transport','Packets / bytes','Names / first packet'],visible.map(f=>[`${f.src}:${f.sourcePort}`,`${f.dst}:${f.destinationPort}`,f.transport,`${number(f.packets)} / ${bytes(f.bytes)}`,`${f.names.join(', ')} · #${f.firstPacket}`]));
  if(tab==='domains')$('#report-content').innerHTML=table(['Name','Packet observations','Observed source IPs','First packet'],visible.map(d=>[d.name,number(d.packets),d.observedFrom.join(', '),`#${d.firstPacket}`]));
}
async function upload(file){
  if(!file || uploadBusy)return;
  if(!/\.pcap(ng)?$/i.test(file.name)){message('Choose a .pcap or .pcapng file.');return;}
  const c=await config();if(file.size>c.maxUploadBytes){message(`File exceeds ${bytes(c.maxUploadBytes)}.`);return;}
  uploadBusy=true;message('');$('#capture').disabled=true;$('#upload-progress').hidden=false;
  try{
    const job=await new Promise((resolve,reject)=>{
      const xhr=new XMLHttpRequest();xhr.open('POST','/api/jobs');xhr.setRequestHeader('Content-Type','application/octet-stream');xhr.setRequestHeader('X-Filename',encodeURIComponent(file.name));if(token)xhr.setRequestHeader('Authorization',`Bearer ${token}`);
      xhr.upload.onprogress=e=>{const percent=e.lengthComputable?Math.round(e.loaded/e.total*100):0;$('#upload-progress progress').value=percent;$('#upload-progress span').textContent=`Uploading ${percent}%`;};
      xhr.onerror=()=>reject(new Error('Upload failed. Check your connection.'));xhr.onload=()=>{let response;try{response=JSON.parse(xhr.responseText);}catch{reject(new Error('Invalid server response.'));return;}if(xhr.status===202)resolve(response);else{if(xhr.status===401)$('#auth-dialog').showModal();reject(new Error(response.error||'Upload failed.'));}};xhr.send(file);
    });
    await openJob(job.id);
  }finally{uploadBusy=false;$('#capture').disabled=false;$('#capture').value='';$('#upload-progress').hidden=true;}
}
async function removeJob(id){
  if(!confirm('Delete this session, its capture, and its report permanently?'))return;
  try{await api(`/api/jobs/${id}`,{method:'DELETE'});clearTimeout(poll);selected=null;report=null;$('#report').hidden=true;$('#job-state').hidden=true;$('#empty').hidden=false;await sessions();message('Session deleted.');}catch(e){message(e.message);}
}
function download(blob,filename){const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),10000);}
$('#capture').addEventListener('change',e=>upload(e.target.files[0]).catch(e=>message(e.message)));
$('#dropzone').addEventListener('dragover',e=>{e.preventDefault();$('#dropzone').classList.add('drag');});
$('#dropzone').addEventListener('dragleave',()=>$('#dropzone').classList.remove('drag'));
$('#dropzone').addEventListener('drop',e=>{e.preventDefault();$('#dropzone').classList.remove('drag');upload(e.dataTransfer.files[0]).catch(e=>message(e.message));});
$('#intel-file').addEventListener('change',async e=>{
  const file=e.target.files[0];if(!file)return;
  try{if(file.size>20*1024*1024)throw new Error('Indicator file must be under 20 MB.');const response=await (await api('/api/indicators',{method:'PUT',headers:{'Content-Type':'application/json'},body:await file.text()})).json();await config();message(`Imported ${number(response.count)} indicators. Future analyses will use this feed.`);}catch(error){message(error.message);}finally{e.target.value='';}
});
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{tab=b.dataset.tab;$('#filter').value='';render();});$('#filter').addEventListener('input',render);
$('#refresh').onclick=()=>sessions().catch(e=>message(e.message));
$('#nav-analysis').onclick=()=>{clearTimeout(poll);selected=null;report=null;$('#report').hidden=true;$('#job-state').hidden=true;$('#empty').hidden=false;sessions().catch(e=>message(e.message));};
$('#auth-button').onclick=()=>$('#auth-dialog').showModal();
$('#save-token').onclick=()=>{token=$('#token').value.trim();sessionStorage.setItem('no-cap-token',token);sessionStorage.removeItem('pcap-lens-token');$('#token').value='';setTimeout(()=>init(),0);};
$('#download-report').onclick=()=>{if(report)download(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}),`${report.session.filename}.report.json`);};
$('#download-capture').onclick=async()=>{try{const response=await api(`/api/jobs/${selected}/capture`);download(await response.blob(),report.session.filename);}catch(e){message(e.message);}};
$('#delete-session').onclick=()=>removeJob(selected);
async function init(){try{await config();const jobs=await sessions();const wanted=new URL(location.href).searchParams.get('session');if(jobs.length && !selected)await openJob(jobs.some(j=>j.id===wanted)?wanted:jobs[0].id);message('');}catch(e){message(e.message);}}
await init();

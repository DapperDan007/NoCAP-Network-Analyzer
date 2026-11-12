// Capture-derived logical groups; these prefixes are display choices, not discovered masks.
export function subnetFor(ip, prefix = 24) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    const octets = ip.split('.').map(Number);
    if (octets.some(n => n > 255)) return null;
    const [a,b] = octets;
    if (!(a === 10 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168)) return null;
    const bits = [16,20,24].includes(Number(prefix)) ? Number(prefix) : 24;
    const value = octets.reduce((v,n)=>(v * 256 + n) >>> 0,0);
    const network = (value & (0xffffffff << (32-bits))) >>> 0;
    return `${[24,16,8,0].map(shift=>(network >>> shift)&255).join('.')}/${bits}`;
  }
  if (!/^f[cd][0-9a-f:]+$/i.test(ip)) return null;
  const sides=ip.toLowerCase().split('::');
  if(sides.length>2)return null;
  const left=sides[0].split(':').filter(Boolean),right=(sides[1]||'').split(':').filter(Boolean);
  const parts=sides.length===2 ? [...left,...Array(Math.max(0,8-left.length-right.length)).fill('0'),...right] : left;
  if(parts.length!==8 || parts.some(p=>!/^[0-9a-f]{1,4}$/.test(p)))return null;
  return `${parts.slice(0,4).map(p=>parseInt(p,16).toString(16)).join(':')}::/64`;
}

export function prepareMap(report, prefix = 24) {
  const hosts=new Map((report.hosts||[]).map(h=>[h.ip,{...h,kind:'host',id:h.ip,weight:0,findings:0}]));
  for(const f of report.flows||[]) for(const ip of [f.src,f.dst]) if(!hosts.has(ip))hosts.set(ip,{id:ip,ip,scope:'unknown',kind:'host',weight:0,names:[],findings:0});
  const groups=new Map();
  for(const h of hosts.values()) {
    const subnet=subnetFor(h.ip,prefix);
    const special=h.scope==='special';
    h.group=subnet ? `subnet:${subnet}` : special ? 'special' : 'external';
    if(!groups.has(h.group))groups.set(h.group,{id:h.group,kind:'group',label:subnet || (special?'Special-use addresses':'External / other endpoints'),scope:subnet?'local':special?'special':'external',members:[],weight:0,findings:0});
    groups.get(h.group).members.push(h.id);
  }
  for(const f of report.findings||[])if(hosts.has(f.device))hosts.get(f.device).findings++;
  for(const f of report.flows||[]) {
    if(hosts.has(f.src))hosts.get(f.src).weight+=Number(f.bytes)||0;
    if(f.dst!==f.src && hosts.has(f.dst))hosts.get(f.dst).weight+=Number(f.bytes)||0;
  }
  for(const g of groups.values())for(const id of g.members){g.weight+=hosts.get(id).weight;g.findings+=hosts.get(id).findings;}
  return {hosts,groups,flows:report.flows||[]};
}

export function buildGraph(model, { expanded=new Set(), includeSpecial=false, focus=null, limit=160 }={}) {
  const selected = focus ? new Set(model.groups.get(focus)?.members || [focus]) : null;
  const allowed = selected ? new Set(selected) : null;
  if(selected)for(const f of model.flows)if(selected.has(f.src)||selected.has(f.dst)){allowed.add(f.src);allowed.add(f.dst);}
  const candidates=new Map(), mapped=new Map();
  for(const h of model.hosts.values()) {
    if(!includeSpecial && h.group==='special' || allowed && !allowed.has(h.id))continue;
    // A focused host must always be individually visible, even if its group is collapsed.
    const id=expanded.has(h.group) || selected?.has(h.id) && !model.groups.has(focus) ? h.id : h.group;
    mapped.set(h.id,id);
    if(!candidates.has(id))candidates.set(id,{...(id===h.id?h:model.groups.get(id)),visibleMembers:[],internalBytes:0,internalPackets:0});
    candidates.get(id).visibleMembers.push(h.id);
  }
  const ranked=[...candidates.values()].sort((a,b)=>(Number(b.id===focus)-Number(a.id===focus))||b.weight-a.weight||a.id.localeCompare(b.id));
  const nodes=ranked.slice(0,limit), visible=new Map(nodes.map(n=>[n.id,n])), links=new Map();
  let omittedFlows=0,hiddenSpecialFlows=0;
  for(const f of model.flows) {
    if(selected && !selected.has(f.src) && !selected.has(f.dst))continue;
    const a=mapped.get(f.src),b=mapped.get(f.dst);
    if(!a||!b){hiddenSpecialFlows++;continue;}
    if(!visible.has(a)||!visible.has(b)){omittedFlows++;continue;}
    if(a===b){const n=visible.get(a);n.internalBytes+=f.bytes;n.internalPackets+=f.packets;continue;}
    const [source,target]=[a,b].sort(),key=JSON.stringify([source,target]);
    if(!links.has(key))links.set(key,{id:key,source,target,bytes:0,packets:0,flows:0,forwardBytes:0,reverseBytes:0,protocols:new Set()});
    const l=links.get(key);l.bytes+=f.bytes;l.packets+=f.packets;l.flows++;l[a===source?'forwardBytes':'reverseBytes']+=f.bytes;l.protocols.add(f.transport);
  }
  const allLinks=[...links.values()].sort((a,b)=>b.bytes-a.bytes);
  return {nodes,links:allLinks.slice(0,500).map(l=>({...l,protocols:[...l.protocols]})),omittedNodes:Math.max(0,candidates.size-limit),omittedFlows,omittedLinks:Math.max(0,allLinks.length-500),hiddenSpecialFlows};
}

export function conversations(model,id) {
  const members=new Set(model.groups.get(id)?.members || [id]);
  const peers=new Map();
  for(const f of model.flows){
    if(!members.has(f.src)&&!members.has(f.dst))continue;
    // Internal group traffic is counted once, with its two explicit endpoints.
    const internal=members.has(f.src)&&members.has(f.dst);
    const peer=internal ? [f.src,f.dst].sort().join(' ↔ ') : members.has(f.src)?f.dst:f.src;
    if(!peers.has(peer))peers.set(peer,{peer,internal,bytes:0,packets:0,sentBytes:0,receivedBytes:0,ports:new Set(),protocols:new Set(),firstPacket:f.firstPacket});
    const p=peers.get(peer);p.bytes+=f.bytes;p.packets+=f.packets;
    if(members.has(f.src))p.sentBytes+=f.bytes;else p.receivedBytes+=f.bytes;
    // A directional flow's destination port is the observed port, not a confirmed service.
    if(f.destinationPort)p.ports.add(`${f.transport}/${f.destinationPort}`);
    p.protocols.add(f.transport);p.firstPacket=Math.min(p.firstPacket,f.firstPacket);
  }
  return [...peers.values()].sort((a,b)=>b.bytes-a.bytes).map(p=>({...p,ports:[...p.ports],protocols:[...p.protocols]}));
}

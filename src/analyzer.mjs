import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { isIP } from 'node:net';
import { indexIntel, normalizeDomain } from './intel.mjs';

export const FIELDS = ['frame.number', 'frame.time_epoch', 'frame.len', 'eth.src', 'eth.dst',
  'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport',
  'udp.dstport', '_ws.col.Protocol', 'dns.qry.name', 'dns.flags.response', 'dns.flags.rcode',
  'tls.handshake.extensions_server_name', 'http.host', 'http.request.method', 'tcp.flags.syn',
  'tcp.flags.ack', 'tcp.analysis.retransmission', 'http.authorization', 'dns.ptr.domain_name'];

export function addressScope(ip) {
  if (isIP(ip) === 4) {
    const [a,b] = ip.split('.').map(Number);
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'local';
    if (a >= 224 || a === 0 || a === 127 || (a === 169 && b === 254)) return 'special';
    return 'external';
  }
  if (isIP(ip) === 6) {
    if (/^f[cd]/i.test(ip)) return 'local';
    if (/^(ff|fe[89ab])/i.test(ip) || ip === '::' || ip === '::1') return 'special';
    return 'external';
  }
  return 'unknown';
}

export class Analysis {
  constructor(intel = { indicators: [] }) {
    this.intel = indexIntel(intel);
    this.hosts = new Map(); this.flows = new Map(); this.domains = new Map();
    this.protocols = new Map(); this.findings = new Map(); this.scans = new Map();
    this.beacons = new Map(); this.nxdomain = new Map(); this.packetCount = 0; this.bytes = 0;
    this.first = Infinity; this.last = -Infinity;
    this.findingsTruncated = false;
  }
  finding(key, finding, packet) {
    if (!this.findings.has(key)) {
      if (this.findings.size >= 2000) { this.findingsTruncated = true; return; }
      this.findings.set(key, { ...finding, count: 0, packets: [] });
    }
    const f = this.findings.get(key); f.count++;
    if (f.packets.length < 10 && !f.packets.includes(packet)) f.packets.push(packet);
  }
  host(ip, mac) {
    if (!this.hosts.has(ip)) {
      if (this.hosts.size >= 5000) throw new Error('Capture exceeds the 5,000-host analysis limit. Split the capture.');
      this.hosts.set(ip, { ip, scope: addressScope(ip), macs: new Set(), sentBytes: 0, receivedBytes: 0,
        packets: 0, names: new Set() });
    }
    const h = this.hosts.get(ip);
    if (mac && h.macs.size < 10) h.macs.add(mac);
    return h;
  }
  add(p) {
    this.packetCount++; const packet = Number(p['frame.number']);
    const time = Number(p['frame.time_epoch']), length = Number(p['frame.len']) || 0;
    this.first = Math.min(this.first, time); this.last = Math.max(this.last, time); this.bytes += length;
    const protocol = p['_ws.col.Protocol'] || 'Unknown';
    this.protocols.set(protocol, (this.protocols.get(protocol) || 0) + 1);
    const src = p['ip.src'] || p['ipv6.src'], dst = p['ip.dst'] || p['ipv6.dst'];
    if (!src || !dst) return;
    const s = this.host(src, p['eth.src']), d = this.host(dst, p['eth.dst']);
    s.sentBytes += length; d.receivedBytes += length; s.packets++; d.packets++;
    const tcp = !!p['tcp.srcport']; const transport = tcp ? 'TCP' : p['udp.srcport'] ? 'UDP' : protocol;
    const sport = p['tcp.srcport'] || p['udp.srcport'] || '', port = p['tcp.dstport'] || p['udp.dstport'] || '';
    const flowKey = JSON.stringify([src,dst,transport,sport,port]);
    if (!this.flows.has(flowKey)) {
      if (this.flows.size >= 50000) throw new Error('Capture exceeds the 50,000-flow analysis limit. Split the capture.');
      this.flows.set(flowKey, { src, dst, transport, sourcePort: sport, destinationPort: port,
        packets: 0, bytes: 0, firstPacket: packet, names: new Set() });
    }
    const flow = this.flows.get(flowKey); flow.packets++; flow.bytes += length;
    const names = [p['dns.qry.name'], p['tls.handshake.extensions_server_name'], p['http.host']].filter(Boolean).map(normalizeDomain);
    for (const name of names) {
      if (!this.domains.has(name)) {
        if (this.domains.size >= 20000) throw new Error('Capture exceeds the 20,000-name analysis limit. Split the capture.');
        this.domains.set(name, { name, packets: 0, firstPacket: packet, observedFrom: new Set() });
      }
      const entry = this.domains.get(name); entry.packets++; if (entry.observedFrom.size < 20) entry.observedFrom.add(src);
      if (flow.names.size < 20) flow.names.add(name);
      // Associate queried names with the requesting endpoint, not the resolver's response address.
      if (p['dns.flags.response'] !== '1' && s.names.size < 100) s.names.add(name);
      const hit = this.intel.domain(name);
      if (hit) this.indicator(hit, `Observed hostname ${name}`, packet, p['dns.flags.response'] === '1' ? dst : src);
    }
    for (const ip of [src, dst]) {
      const hit = this.intel.ip(ip);
      if (hit) this.indicator(hit, `Packet involving ${ip}`, packet, ip === dst ? src : dst);
    }
    if (p['http.authorization']?.toLowerCase().startsWith('basic ')) this.finding(`basic:${src}:${dst}`, {
      severity: 'high', title: 'Basic authorization visible over plaintext HTTP', device: src, confidence: 'high',
      evidence: `HTTP Basic authorization was observed between ${src} and ${dst}. Credential values are omitted from this report.`,
      action: 'Replace HTTP with HTTPS and consider rotating the exposed credential.' }, packet);
    if (tcp && p['tcp.flags.syn'] === '1' && p['tcp.flags.ack'] === '0' && !p['tcp.analysis.retransmission']) {
      if (['21','23'].includes(port)) this.finding(`plain:${src}:${dst}:${port}`, {
        severity: 'medium', title: `Connection attempt to ${port === '23' ? 'Telnet' : 'FTP'} port`, device: src,
        confidence: 'medium', evidence: `TCP SYN to ${dst}:${port}; port alone does not confirm the application or a successful connection.`,
        action: 'Check whether the destination exposes an insecure service and disable it if unnecessary.' }, packet);
      // Scan heuristic is limited to a rolling one-minute window and SYN connection attempts.
      if (!this.scans.has(src)) this.scans.set(src, []);
      const attempts = this.scans.get(src); attempts.push({ time, dst, port, packet });
      while (attempts.length && (time - attempts[0].time > 60 || attempts.length > 1000)) attempts.shift();
      const targets = new Set(attempts.map(x=>x.dst)), ports = new Set(attempts.map(x=>x.port));
      if (targets.size >= 20 || ports.size >= 20) this.finding(`scan:${src}`, {
        severity: 'medium', title: 'Possible network scanning', device: src, confidence: 'medium',
        evidence: `At least ${targets.size} destinations and ${ports.size} destination ports in a 60-second SYN window.`,
        action: 'Check for legitimate discovery or scanning software before treating this as malicious.' }, packet);
      const beaconKey = JSON.stringify([src,dst,port]);
      if (!this.beacons.has(beaconKey)) this.beacons.set(beaconKey, { src, dst, port, times: [], packets: [] });
      const b = this.beacons.get(beaconKey);
      if (b.times.length < 1000) { b.times.push(time); b.packets.push(packet); }
    }
    if (p['dns.flags.response'] === '1' && p['dns.flags.rcode'] === '3') {
      if (!this.nxdomain.has(dst)) this.nxdomain.set(dst, { count: 0, names: new Set(), packets: [] });
      const n = this.nxdomain.get(dst); n.count++; if (n.names.size < 1000) n.names.add(p['dns.qry.name']);
      if (n.packets.length < 10) n.packets.push(packet);
    }
  }
  indicator(hit, evidence, packet, device) {
    const stale = Date.now() - Date.parse(hit.updated) > 30 * 86400000;
    this.finding(`intel:${hit.type}:${hit.value}:${device}`, { severity: stale ? 'medium' : 'high',
      title: `${stale ? 'Stale threat-indicator' : 'Threat-indicator'} match`, device, confidence: stale ? 'low' : 'medium',
      evidence: `${evidence}; matched ${hit.type} ${hit.value}. Source: ${hit.source}; updated ${hit.updated}.`,
      action: 'Validate the feed classification and connection context. Shared infrastructure and stale intelligence can produce false positives.',
      indicator: hit }, packet);
  }
  finish() {
    for (const b of this.beacons.values()) {
      if (b.times.length < 8 || addressScope(b.dst) !== 'external') continue;
      const times = [...b.times].sort((a,c)=>a-c), gaps = times.slice(1).map((t,i)=>t-times[i]);
      const mean = gaps.reduce((a,c)=>a+c,0)/gaps.length;
      const cv = Math.sqrt(gaps.reduce((a,c)=>a+(c-mean)**2,0)/gaps.length)/mean;
      if (mean >= 5 && cv <= .1) this.finding(`beacon:${b.src}:${b.dst}:${b.port}`, {
        severity: 'info', title: 'Periodic outbound connection attempts', device: b.src, confidence: 'low',
        evidence: `${b.times.length} SYN attempts to ${b.dst}:${b.port}, average interval ${mean.toFixed(1)}s (variation ${(cv*100).toFixed(1)}%).`,
        action: 'Compare with expected device polling or keepalive behavior. Periodicity alone is not evidence of malware.' }, b.packets[0]);
    }
    for (const [device,n] of this.nxdomain) if (n.count >= 20 && n.names.size >= 10)
      this.finding(`dns:${device}`, { severity: 'medium', title: 'Repeated DNS name failures', device, confidence: 'low',
        evidence: `${n.count} NXDOMAIN response packets involving ${n.names.size} distinct names addressed to this endpoint. Retries may inflate counts.`,
        action: 'Check DNS configuration, outdated applications, and the queried names. This is a heuristic, not a malware verdict.' }, n.packets[0]);
    const findings = [...this.findings.values()].sort((a,b)=>({high:0,medium:1,info:2}[a.severity]-{high:0,medium:1,info:2}[b.severity]));
    const report = {
      summary: { packets: this.packetCount, bytes: this.bytes, start: this.packetCount ? this.first : null,
        end: this.packetCount ? this.last : null, duration: this.packetCount ? Math.max(0,this.last-this.first) : 0,
        hosts: this.hosts.size, flows: this.flows.size, domains: this.domains.size, findings: findings.length },
      intelligence: { indicators: this.intel.count, importedAt: this.intel.importedAt,
        status: this.intel.count ? 'Checked against locally imported indicators only' : 'Not checked — no threat indicators imported' },
      hosts: [...this.hosts.values()].map(h=>({ ...h, macs: [...h.macs], names: [...h.names],
        identity: this.identity(h) })).sort((a,b)=>b.sentBytes+b.receivedBytes-a.sentBytes-a.receivedBytes),
      flows: [...this.flows.values()].map(f=>({...f,names:[...f.names]})).sort((a,b)=>b.bytes-a.bytes),
      domains: [...this.domains.values()].map(d=>({...d,observedFrom:[...d.observedFrom]})).sort((a,b)=>b.packets-a.packets),
      protocols: [...this.protocols].map(([name,packets])=>({name,packets})).sort((a,b)=>b.packets-a.packets),
      findings,
      limitations: [
        'Only traffic present in this capture was assessed. Same-subnet traffic and idle devices may be absent.',
        'Private IPv4 and ULA IPv6 addresses are marked local. Public IPv6 devices may belong to your LAN; scope is an address classification, not ownership.',
        'Encrypted payloads, encrypted DNS, VPNs, and encrypted client hello limit visibility.',
        'MAC addresses may identify the next-hop router rather than the originating device across routed networks.',
        'Device labels are low-confidence guesses from contacted names, not verified model or firmware identification.',
        'No exploit signature engine or CVE/firmware verification is included. No findings does not mean a device is safe.',
        'Bytes are observed frame lengths, including headers, retries, and any duplicate packets; they are not application upload measurements.',
        'Rules analyze observed metadata; no AI model or external lookup service is used.'
      ]
    };
    if (this.findingsTruncated) report.limitations.unshift('Finding groups exceeded 2,000; additional groups were omitted. Narrow or split the capture.');
    return report;
  }
  identity(h) {
    if (h.scope === 'special') return 'Multicast / special-use endpoint';
    if (h.scope === 'external') return 'Public-address endpoint';
    const names = [...h.names].join(' ');
    if (/(^|\s|\.)roku\.(com|net)/.test(names)) return 'Possible Roku device · low confidence';
    if (/(^|\s|\.)ring\.com/.test(names)) return 'Possible Ring ecosystem device · low confidence';
    if (/(^|\s|\.)sonos\.com/.test(names)) return 'Possible Sonos device · low confidence';
    return 'Unidentified local endpoint';
  }
}

export async function analyzeCapture(path, intel, { timeoutMs = 180000, maxPackets = 500000, onProgress = ()=>{} } = {}) {
  const analysis = new Analysis(intel);
  const args = ['-n','-r',path,'-c',String(maxPackets + 1),'-T','fields','-E','separator=/t','-E','occurrence=f'];
  for (const field of FIELDS) args.push('-e',field);
  const child = spawn(process.env.TSHARK_PATH || 'tshark', args, { windowsHide: true, stdio:['ignore','pipe','pipe'] });
  let stderr = '', expired = false, parseError;
  child.stderr.on('data',chunk=>{ if (stderr.length < 8192) stderr += chunk.toString().slice(0,8192-stderr.length); });
  const timer = setTimeout(()=>{ expired = true; child.kill('SIGKILL'); },timeoutMs);
  const exited = new Promise((resolve,reject)=>{ child.once('error',reject); child.once('close',code=>resolve(code)); });
  // Attach the rejection handler immediately, before reading stdout.
  const completion = exited.then(code=>({code}),error=>({error}));
  try {
    for await (const line of createInterface({ input: child.stdout, crlfDelay: Infinity })) {
      if (analysis.packetCount >= maxPackets) continue;
      try {
        const values = line.split('\t');
        analysis.add(Object.fromEntries(FIELDS.map((f,i)=>[f,values[i] || ''])));
        if (analysis.packetCount % 10000 === 0) onProgress(analysis.packetCount);
      } catch(error) { parseError = error; child.kill('SIGKILL'); break; }
    }
    const { code, error } = await completion;
    if (error) throw new Error('TShark could not start. Use the Docker image, which includes TShark.');
    if (expired) throw new Error('Analysis time limit reached. Split the capture into smaller files.');
    if (parseError) throw parseError;
    if (code !== 0) throw new Error(`TShark rejected the capture: ${stderr.trim().slice(0,1000) || 'invalid or unsupported file'}`);
    const report = analysis.finish();
    // Conservative notice even when exactly maxPackets were present.
    if (analysis.packetCount >= maxPackets) report.limitations.unshift(`Analysis stopped at ${maxPackets.toLocaleString()} packets; this report may cover only part of the capture.`);
    if (stderr.trim()) report.parserWarning = stderr.trim().slice(0,1000);
    return report;
  } finally { clearTimeout(timer); }
}

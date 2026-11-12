import http from 'node:http';
import { promises as fs, createWriteStream, createReadStream } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { analyzeCapture } from './analyzer.mjs';
import { validateIntel } from './intel.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const data = path.resolve(process.env.DATA_DIR || path.join(root,'data'));
const maxUpload = Number(process.env.MAX_UPLOAD_MB || 250) * 1024 * 1024;
const maxStorage = Number(process.env.MAX_STORAGE_MB || 2048) * 1024 * 1024;
const timeoutMs = Number(process.env.ANALYSIS_TIMEOUT_SECONDS || 180) * 1000;
const token = process.env.API_TOKEN || '';
const jobs = new Map(); let running = false, uploading = 0, reserved = 0;
const jobsDir = path.join(data,'jobs');
await fs.mkdir(jobsDir,{ recursive:true });
const jobPath = (id,file)=>path.join(jobsDir,id,file);
async function atomicJSON(file,value) { const tmp=`${file}.${randomUUID()}.tmp`; await fs.writeFile(tmp,JSON.stringify(value)); await fs.rename(tmp,file); }
async function save(job) { await atomicJSON(jobPath(job.id,'job.json'),job); }
async function readIntel() {
  try { return JSON.parse(await fs.readFile(path.join(data,'indicators.json'),'utf8')); }
  catch(e) { if (e.code === 'ENOENT') return { indicators:[] }; throw e; }
}
for (const entry of await fs.readdir(jobsDir,{withFileTypes:true})) {
  if (!entry.isDirectory() || !/^[a-f0-9-]{36}$/.test(entry.name)) continue;
  try {
    const job = JSON.parse(await fs.readFile(jobPath(entry.name,'job.json'),'utf8'));
    if (['running','queued'].includes(job.status)) { job.status = 'queued'; job.processedPackets = 0; }
    if (job.status === 'uploading') { job.status = 'failed'; job.error = 'Upload interrupted by application restart. Delete this session and upload again.'; }
    jobs.set(entry.name,job); await save(job);
  } catch { /* Ignore an incomplete, unregistered job directory. */ }
}
async function work() {
  if (running) return;
  running = true;
  try {
    for (const job of jobs.values()) {
      if (job.status !== 'queued') continue;
      job.status = 'running'; await save(job);
      try {
        const intel = await readIntel();
        const report = await analyzeCapture(jobPath(job.id,'capture.pcap'),intel,{ timeoutMs,
          onProgress:count=>{job.processedPackets=count;} });
        report.session = { id:job.id, filename:job.filename, analyzedAt:new Date().toISOString(), engine:'TShark + PCAP Lens rules v0.1' };
        await atomicJSON(jobPath(job.id,'report.json'),report);
        job.summary = report.summary; job.status = 'complete'; job.processedPackets = report.summary.packets;
      } catch(error) { job.status = 'failed'; job.error = error.message; }
      job.finishedAt = new Date().toISOString(); await save(job);
    }
  } finally { running = false; }
}
function json(res,status,value) { res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'}); res.end(JSON.stringify(value)); }
function reject(status,message) { const e = new Error(message); e.status = status; throw e; }
async function body(req,limit) {
  let size = 0; const chunks=[];
  for await (const chunk of req) { size += chunk.length; if (size > limit) reject(413,'Request exceeds the size limit.'); chunks.push(chunk); }
  return Buffer.concat(chunks);
}
function authorize(req) {
  let hostname;
  try { hostname = new URL(`http://${req.headers.host}`).hostname; } catch { reject(400,'Invalid host header.'); }
  if (!token && !['localhost','127.0.0.1','[::1]'].includes(hostname))
    reject(403,'Configure API_TOKEN before accessing the API with a non-local hostname.');
  // Only same-origin browser mutations; never trust the Host header as an access-control boundary.
  if (!['GET','HEAD'].includes(req.method) && req.headers.origin) {
    let origin; try { origin = new URL(req.headers.origin); } catch { reject(403,'Invalid request origin.'); }
    if (origin.host !== req.headers.host) reject(403,'Cross-origin requests are not allowed.');
  }
  // Docker NAT may rewrite localhost source addresses. Compose binds the published port to localhost.
  // A token is mandatory when explicitly enabling remote access.
  if (process.env.REQUIRE_AUTH === 'true' && !token) reject(503,'Configure API_TOKEN before enabling remote access.');
  if (!token) return;
  const supplied = Buffer.from(String(req.headers.authorization || '').replace(/^Bearer /,''));
  const expected = Buffer.from(token);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied,expected)) reject(401,'Enter the configured API token.');
}
const staticFiles = { '/':'index.html','/app.js':'app.js','/style.css':'style.css',
  '/map':'map.html','/map.js':'map.js','/map-model.js':'map-model.js','/map.css':'map.css' };
const server = http.createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  try {
    const url = new URL(req.url,'http://localhost');
    if (url.pathname === '/health' && req.method === 'GET') return json(res,200,{status:'ok'});
    if (staticFiles[url.pathname] && req.method === 'GET') {
      res.setHeader('Content-Type',url.pathname.endsWith('.js')?'text/javascript':url.pathname.endsWith('.css')?'text/css':'text/html');
      res.end(await fs.readFile(path.join(root,'public',staticFiles[url.pathname]))); return;
    }
    authorize(req);
    if (url.pathname === '/api/config' && req.method === 'GET') {
      const intel = await readIntel();
      return json(res,200,{maxUploadBytes:maxUpload,maxStorageBytes:maxStorage,indicators:intel.indicators.length,
        importedAt:intel.importedAt || null,authenticated:!!token});
    }
    if (url.pathname === '/api/indicators' && req.method === 'PUT') {
      const input = JSON.parse((await body(req,20*1024*1024)).toString());
      let intel; try { intel = validateIntel(input); } catch(error) { reject(400,error.message); }
      await atomicJSON(path.join(data,'indicators.json'),intel);
      return json(res,200,{count:intel.indicators.length,importedAt:intel.importedAt});
    }
    if (url.pathname === '/api/jobs' && req.method === 'GET')
      return json(res,200,[...jobs.values()].sort((a,b)=>b.createdAt.localeCompare(a.createdAt)));
    if (url.pathname === '/api/jobs' && req.method === 'POST') {
      if (uploading || [...jobs.values()].filter(j=>['queued','running'].includes(j.status)).length >= 8) reject(429,'Upload or analysis queue is busy. Try again shortly.');
      if (!['application/octet-stream','application/vnd.tcpdump.pcap'].includes((req.headers['content-type']||'').split(';')[0])) reject(415,'Send a raw PCAP body.');
      const length = Number(req.headers['content-length']);
      if (!Number.isSafeInteger(length) || length < 4 || length > maxUpload) reject(413,'A capture with a valid Content-Length within the upload limit is required.');
      let filename;
      try { filename = decodeURIComponent(req.headers['x-filename'] || 'capture.pcap'); } catch { reject(400,'Invalid filename.'); }
      filename = filename.split(/[\\/]/).at(-1).replace(/[\x00-\x1f]/g,'').slice(0,200);
      if (!/\.pcap(ng)?$/i.test(filename)) reject(400,'Choose a .pcap or .pcapng file.');
      const used = [...jobs.values()].reduce((sum,j)=>sum+(j.size||0),0);
      if (used + reserved + length > maxStorage) reject(413,'Capture storage limit reached. Delete older sessions.');
      const job = {id:randomUUID(),filename,size:length,createdAt:new Date().toISOString(),status:'uploading',processedPackets:0};
      uploading++; reserved += length; let received=0;
      try {
        await fs.mkdir(path.join(jobsDir,job.id)); await save(job);
        const limiter = new Transform({transform(chunk,encoding,callback) {
          received += chunk.length;
          callback(received > length || received > maxUpload ? new Error('Upload exceeds declared size.') : null,chunk);
        }});
        await pipeline(req,limiter,createWriteStream(jobPath(job.id,'capture.part')));
        if (received !== length) reject(400,'Incomplete capture upload.');
        const handle = await fs.open(jobPath(job.id,'capture.part'),'r');
        const magic=Buffer.alloc(4); try {await handle.read(magic,0,4,0);} finally {await handle.close();}
        if (!['d4c3b2a1','a1b2c3d4','4d3cb2a1','a1b23c4d','0a0d0d0a'].includes(magic.toString('hex'))) reject(400,'File header is not PCAP or PCAPNG.');
        await fs.rename(jobPath(job.id,'capture.part'),jobPath(job.id,'capture.pcap'));
        job.status='queued'; jobs.set(job.id,job); await save(job);
        json(res,202,job); void work().catch(error=>console.error('Queue error:',error.message)); return;
      } catch(error) { jobs.delete(job.id); await fs.rm(path.join(jobsDir,job.id),{recursive:true,force:true}); throw error; }
      finally { uploading--; reserved -= length; }
    }
    const match = /^\/api\/jobs\/([a-f0-9-]{36})(?:\/(report|capture))?$/.exec(url.pathname);
    if (match) {
      const [,id,kind] = match; const job = jobs.get(id);
      if (!job) reject(404,'Session not found.');
      if (req.method === 'DELETE' && !kind) {
        if (['queued','running','uploading'].includes(job.status)) reject(409,'Wait for analysis to finish before deleting.');
        await fs.rm(path.join(jobsDir,id),{recursive:true,force:true}); jobs.delete(id); return json(res,200,{deleted:true});
      }
      if (req.method === 'GET' && !kind) return json(res,200,job);
      if (req.method === 'GET' && kind === 'report') {
        if (job.status !== 'complete') reject(409,'Report is not ready.');
        return json(res,200,JSON.parse(await fs.readFile(jobPath(id,'report.json'),'utf8')));
      }
      if (req.method === 'GET' && kind === 'capture') {
        if (job.status !== 'complete' && job.status !== 'failed') reject(409,'Capture is still being processed.');
        res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':'attachment; filename="capture.pcap"','Cache-Control':'no-store'});
        await pipeline(createReadStream(jobPath(id,'capture.pcap')),res); return;
      }
    }
    reject(404,'Not found.');
  } catch(error) {
    if (!res.headersSent && !res.destroyed) json(res,error.status || (error instanceof SyntaxError ? 400 : 500),{error:error.status || error instanceof SyntaxError ? error.message : 'Request failed. Check server logs.'});
    if (!error.status && !(error instanceof SyntaxError)) console.error(error.message);
  }
});
server.requestTimeout = 300000;
server.headersTimeout = 30000;
server.listen(Number(process.env.PORT || 8080),process.env.HOST || '127.0.0.1',()=>{
  console.log(`PCAP Lens listening on port ${process.env.PORT || 8080}. Captures and reports remain in ${data}.`);
  void work().catch(error=>console.error('Queue error:',error.message));
});

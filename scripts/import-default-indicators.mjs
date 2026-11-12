import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateIntel } from '../src/intel.mjs';

// Downloads only these publisher-controlled feed files; never visits indicator hosts.
const feeds = [
  { type: 'ip', name: 'Threatview IP High Confidence', url: 'https://threatview.io/Downloads/IP-High-Confidence-Feed.txt' },
  { type: 'domain', name: 'Threatview Domain High Confidence', url: 'https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt' }
];
const importing = process.argv.includes('--import');
const replace = process.argv.includes('--replace');
const base = new URL(process.env.PCAP_LENS_URL || 'http://localhost:8080');
if (!['http:', 'https:'].includes(base.protocol) || !['localhost', '127.0.0.1', '[::1]'].includes(base.hostname))
  throw new Error('PCAP_LENS_URL must target this machine via localhost or a loopback address.');
const headers = process.env.API_TOKEN ? { Authorization: `Bearer ${process.env.API_TOKEN}` } : {};
async function api(route, options = {}) {
  const response = await fetch(new URL(route, base), { ...options, headers: { ...headers, ...options.headers }, signal: AbortSignal.timeout(30000) });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `API returned ${response.status}`);
  return result;
}
if (importing) {
  const config = await api('/api/config');
  if (config.indicators && !replace) throw new Error('An indicator set is already installed. Import replaces it; use --replace only when you intend to replace that set.');
}
const downloaded = await Promise.all(feeds.map(async feed => {
  const response = await fetch(feed.url, { signal: AbortSignal.timeout(30000), redirect: 'error' });
  if (!response.ok) throw new Error(`${feed.name}: HTTP ${response.status}`);
  if (Number(response.headers.get('content-length')) > 10 * 1024 * 1024) throw new Error(`${feed.name}: feed exceeds 10 MiB`);
  let bytes = 0; const chunks = [];
  for await (const chunk of response.body) {
    bytes += chunk.length;
    if (bytes > 10 * 1024 * 1024) throw new Error(`${feed.name}: feed exceeds 10 MiB`);
    chunks.push(Buffer.from(chunk));
  }
  const fetchedAt = new Date().toISOString();
  const lastModified = response.headers.get('last-modified');
  const dated = lastModified && Number.isFinite(Date.parse(lastModified));
  const updated = dated ? new Date(lastModified).toISOString() : fetchedAt;
  const values = [...new Set(Buffer.concat(chunks).toString('utf8').replace(/^\uFEFF/, '').split(/\r?\n/)
    .map(line => line.trim()).filter(line => line && !line.startsWith('#') && !line.startsWith('!')))];
  if (!values.length) throw new Error(`${feed.name}: empty feed; existing indicators were not changed`);
  // This timestamp describes the publisher's feed snapshot, not when each IOC was last seen.
  const source = `${feed.name} (${dated ? 'feed snapshot' : 'retrieved'}); ${feed.url}`;
  return {
    indicators: values.map(value => ({ type: feed.type, value, source, updated })),
    metadata: { ...feed, count: values.length, fetchedAt, lastModified: dated ? updated : null, timestampMeaning: dated ? 'Feed file Last-Modified; not individual IOC last-seen' : 'Retrieval time; publisher supplied no Last-Modified' }
  };
}));
const result = validateIntel({ indicators: downloaded.flatMap(feed => feed.indicators) });
const outputDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../data');
await mkdir(outputDir, { recursive: true });
await writeFile(path.join(outputDir, 'default-indicators.json'), JSON.stringify({ indicators: result.indicators }));
await writeFile(path.join(outputDir, 'default-indicators.sources.json'), JSON.stringify({ fetchedAt: new Date().toISOString(), feeds: downloaded.map(feed => feed.metadata) }, null, 2));
console.log(JSON.stringify({ file: path.join(outputDir, 'default-indicators.json'), total: result.indicators.length, feeds: downloaded.map(feed => feed.metadata) }, null, 2));
if (importing) {
  const imported = await api('/api/indicators', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ indicators: result.indicators }) });
  const verified = await api('/api/config');
  if (verified.indicators !== imported.count || verified.importedAt !== imported.importedAt) throw new Error('Import could not be verified; check the tool.');
  console.log(`Verified import: ${verified.indicators} indicators installed at ${verified.importedAt}. Existing reports are unchanged.`);
}

import { isIP } from 'node:net';

export function normalizeDomain(value) {
  return String(value || '').toLowerCase().replace(/\.$/, '');
}

export function validateIntel(input) {
  if (!input || !Array.isArray(input.indicators) || input.indicators.length > 100000)
    throw new Error('Expected an indicators array with at most 100,000 entries.');
  const indicators = input.indicators.map(item => {
    if (!item || !['ip', 'domain'].includes(item.type)) throw new Error('Indicator type must be ip or domain.');
    const value = item.type === 'domain' ? normalizeDomain(item.value) : String(item.value || '').toLowerCase();
    if (item.type === 'ip' ? !isIP(value) : !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(value))
      throw new Error('Invalid indicator value.');
    if (!item.source || String(item.source).length > 200) throw new Error('Each indicator needs a source (up to 200 characters).');
    if (!item.updated || !Number.isFinite(Date.parse(item.updated))) throw new Error('Each indicator needs an updated ISO date.');
    if (Date.parse(item.updated) > Date.now() + 86400000) throw new Error('Indicator dates cannot be in the future.');
    return { type: item.type, value, source: String(item.source), updated: new Date(item.updated).toISOString() };
  });
  return { indicators, importedAt: new Date().toISOString() };
}

export function indexIntel(intel = { indicators: [] }) {
  const ips = new Map(), domains = new Map();
  for (const item of intel.indicators) (item.type === 'ip' ? ips : domains).set(item.value, item);
  return {
    count: intel.indicators.length,
    importedAt: intel.importedAt || null,
    ip: value => ips.get(value?.toLowerCase()),
    domain(value) {
      const labels = normalizeDomain(value).split('.');
      while (labels.length >= 2) {
        const hit = domains.get(labels.join('.'));
        if (hit) return hit;
        labels.shift();
      }
    }
  };
}

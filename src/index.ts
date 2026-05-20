import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import * as dns from 'node:dns';
import * as https from 'node:https';
import * as http from 'node:http';
import * as tls from 'node:tls';
import { createRequire } from 'node:module';
import { z } from 'zod';
import { detectTech } from './tech-patterns.js';

const require = createRequire(import.meta.url);
const whois = require('whois');

const server = new McpServer({
  name: 'domain-intel',
  version: '1.0.0',
}, {
  capabilities: { tools: {} },
});

function fetchUrl(url: string, timeout = 15000): Promise<{
  statusCode?: number; headers: Record<string, string>; body: string; error?: string; timing: number;
}> {
  return new Promise((resolve) => {
    const start = Date.now();
    const parsed = new URL(url);
    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.get(url, {
      timeout,
      headers: {
        'user-agent': 'Mozilla/5.0 (compatible; DomainIntel/1.0; +https://mcpize.com/mcp/domain-intel)',
        'accept': 'text/html,application/xhtml+xml',
      },
    }, (res) => {
      const statusCode = res.statusCode;
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        headers[k] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
      }
      let body = '';
      let maxBytes = 100000;
      res.on('data', (chunk: Buffer) => {
        if (body.length < maxBytes) body += chunk.toString().slice(0, maxBytes - body.length);
      });
      res.on('end', () => {
        resolve({ statusCode, headers, body, timing: Date.now() - start, error: body.length >= maxBytes ? 'Body truncated to 100KB' : undefined });
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ headers: {}, body: '', error: 'Request timed out', timing: Date.now() - start }); });
    req.on('error', (err) => resolve({ headers: {}, body: '', error: err.message, timing: Date.now() - start }));
  });
}

function resolveDns(domain: string): Promise<Record<string, string[]>> {
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'] as const;
  return Promise.all(types.map(async (type) => {
    try {
      const result = await dns.promises.resolve(domain, type);
      return [type, (Array.isArray(result) ? result : [result]).map(r => {
        if (typeof r === 'object' && r !== null && 'exchange' in r) {
          return `${(r as any).exchange} (priority ${(r as any).priority})`;
        }
        return String(r);
      })] as const;
    } catch { return [type, []] as const; }
  })).then(entries => Object.fromEntries(entries));
}

function checkEmailSecurity(records: Record<string, string[]>): {
  spf: { present: boolean; record?: string };
  dmarc: { present: boolean; record?: string };
  dkim: { present: boolean; domains?: string[] };
  mxRecords: string[];
} {
  const spfRecord = (records.TXT || []).find(r => r.startsWith('v=spf1'));
  const dmarcRecord = (records.TXT || []).find(r => r.startsWith('v=DMARC1'));
  const mxStrings = (records.MX || []).map(mx => {
    if (mx.startsWith('{')) return mx;
    return mx;
  });
  const mxJoined = mxStrings.join(' ');
  const googleMx = /google/i.test(mxJoined);
  const microsoftMx = /outlook|protection\.outlook|microsoft/i.test(mxJoined);
  return {
    spf: { present: !!spfRecord, record: spfRecord },
    dmarc: { present: !!dmarcRecord, record: dmarcRecord },
    dkim: { present: googleMx || microsoftMx, domains: googleMx ? ['Google Workspace'] : microsoftMx ? ['Microsoft 365'] : undefined },
    mxRecords: mxStrings,
  };
}

function extractSeoMeta(headers: Record<string, string>, body: string) {
  const title = body.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim();
  const desc = body.match(/<meta\s+[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i)?.[1] ||
               body.match(/<meta\s+[^>]*content=["']([^"']*)["'][^>]*name=["']description["']/i)?.[1];
  const ogTitle = body.match(/<meta\s+[^>]*property=["']og:title["'][^>]*content=["']([^"']*)["']/i)?.[1];
  const ogDesc = body.match(/<meta\s+[^>]*property=["']og:description["'][^>]*content=["']([^"']*)["']/i)?.[1];
  const ogImage = body.match(/<meta\s+[^>]*property=["']og:image["'][^>]*content=["']([^"']*)["']/i)?.[1];
  const lang = body.match(/<html[^>]*lang=["']([^"']*)["']/i)?.[1];
  const canonical = body.match(/<link\s+[^>]*rel=["']canonical["'][^>]*href=["']([^"']*)["']/i)?.[1];
  return { title, description: desc, ogTitle, ogDescription: ogDesc, ogImage, language: lang, canonical };
}

function extractSocialLinks(body: string) {
  const links: Record<string, string> = {};
  const patterns: Record<string, RegExp> = {
    'Twitter/X': /https:\/\/(?:www\.)?(?:twitter\.com|x\.com)\/([a-zA-Z0-9_]+)/gi,
    'LinkedIn': /https:\/\/(?:www\.)?linkedin\.com\/(?:company|in)\/[a-zA-Z0-9_-]+/gi,
    'GitHub': /https:\/\/(?:www\.)?github\.com\/[a-zA-Z0-9_-]+/gi,
    'YouTube': /https:\/\/(?:www\.)?youtube\.com\/(?:@|channel\/|c\/|user\/)[a-zA-Z0-9_-]+/gi,
    'Instagram': /https:\/\/(?:www\.)?instagram\.com\/[a-zA-Z0-9_.]+/gi,
    'Facebook': /https:\/\/(?:www\.)?facebook\.com\/[a-zA-Z0-9.]+/gi,
    'TikTok': /https:\/\/(?:www\.)?tiktok\.com\/@[a-zA-Z0-9_.]+/gi,
    'Reddit': /https:\/\/(?:www\.)?reddit\.com\/(?:r|user)\/[a-zA-Z0-9_]+/gi,
  };
  for (const [name, pattern] of Object.entries(patterns)) {
    const match = body.match(pattern);
    if (match) links[name] = match[0];
  }
  return links;
}

function checkSecurityHeaders(headers: Record<string, string>) {
  const checks = [
    { header: 'strict-transport-security', name: 'HSTS', desc: 'Forces HTTPS connections', severity: 'high', present: !!headers['strict-transport-security'] },
    { header: 'content-security-policy', name: 'CSP', desc: 'Controls resource loading', severity: 'high', present: !!headers['content-security-policy'] },
    { header: 'x-frame-options', name: 'X-Frame-Options', desc: 'Prevents clickjacking', severity: 'high', present: !!headers['x-frame-options'] },
    { header: 'x-content-type-options', name: 'X-Content-Type-Options', desc: 'Prevents MIME sniffing', severity: 'high', present: !!headers['x-content-type-options'] },
    { header: 'x-xss-protection', name: 'X-XSS-Protection', desc: 'Cross-site scripting filter', severity: 'medium', present: !!headers['x-xss-protection'] },
    { header: 'referrer-policy', name: 'Referrer-Policy', desc: 'Controls referrer info', severity: 'medium', present: !!headers['referrer-policy'] },
    { header: 'permissions-policy', name: 'Permissions-Policy', desc: 'Controls browser features', severity: 'medium', present: !!headers['permissions-policy'] },
    { header: 'access-control-allow-origin', name: 'CORS', desc: 'Cross-origin access policy', severity: 'info', present: !!headers['access-control-allow-origin'] },
    { header: 'x-robots-tag', name: 'X-Robots-Tag', desc: 'Search engine indexing directives', severity: 'info', present: !!headers['x-robots-tag'] },
  ];
  const present = checks.filter(c => c.present).map(c => ({ name: c.name, desc: c.desc, severity: c.severity, value: String(headers[c.header] ?? '') }));
  const missing = checks.filter(c => !c.present).map(c => ({ name: c.name, desc: c.desc, severity: c.severity }));
  return { score: Math.round(present.length / checks.length * 100), present, missing };
}

function checkSsl(domain: string, port = 443): Promise<{
  valid: boolean; validTo?: string; validFrom?: string; issuer?: string; subject?: string; sans?: string[]; expired: boolean; error?: string;
}> {
  return new Promise((resolve) => {
    const socket = tls.connect(port, domain, { servername: domain, timeout: 10000 }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.valid_to) return resolve({ valid: false, expired: true, error: 'No certificate returned' });
      const expired = new Date(cert.valid_to) < new Date();
      resolve({
        valid: !expired, validTo: cert.valid_to, validFrom: cert.valid_from,
        issuer: String(cert.issuer?.O?.[0] ?? cert.issuer?.O ?? cert.issuer?.CN?.[0] ?? cert.issuer?.CN ?? ''),
        subject: String(cert.subject?.CN?.[0] ?? cert.subject?.CN ?? ''),
        sans: cert.subjectaltname?.split(', ').filter(Boolean) || [],
        expired,
      });
    });
    socket.on('error', (err) => resolve({ valid: false, expired: false, error: err.message }));
    socket.setTimeout(10000, () => { socket.destroy(); resolve({ valid: false, expired: false, error: 'Connection timed out' }); });
  });
}

function whoisLookup(domain: string): Promise<string> {
  return new Promise((resolve) => {
    (whois as any).lookup(domain, (err: Error | null, data: string) => {
      resolve(err ? `WHOIS lookup failed: ${err.message}` : String(data).substring(0, 10000));
    });
  });
}

function extractRegistrarInfo(whoisText: string) {
  const registrar = whoisText.match(/Registrar:\s*(.+)/i)?.[1]?.trim();
  const creationDate = whoisText.match(/Creation Date:\s*(.+)/i)?.[1]?.trim() || whoisText.match(/created:\s*(.+)/i)?.[1]?.trim();
  const expiryDate = whoisText.match(/Registry Expiry Date:\s*(.+)/i)?.[1]?.trim() || whoisText.match(/Expir(y|ation) Date:\s*(.+)/i)?.[2]?.trim();
  const nameServers = whoisText.match(/(?:Name Server|nserver):\s*([a-zA-Z0-9.-]+)/gi)?.slice(0, 5).map(s => s.replace(/^[^:]*:\s*/, ''));
  return { registrar, creationDate, expiryDate, nameServers: nameServers || [] };
}

server.registerTool('tech_detect', {
  description: 'Detect technologies used by a website. Given a URL, identify CMS, frameworks, analytics tools, CDN, hosting provider, payment processors, and more. Uses only HTTP headers and HTML parsing — no scraping or third-party APIs.',
  inputSchema: z.object({
    url: z.string().describe('Full URL to analyze (e.g. https://example.com)'),
  }),
}, async ({ url }) => {
  const { statusCode, headers, body, error, timing } = await fetchUrl(url);
  if (error && !body) return { content: [{ type: 'text', text: JSON.stringify({ url, error }, null, 2) }] };
  const tech = detectTech(headers, body);
  return {
    content: [{ type: 'text', text: JSON.stringify({
      url, statusCode, timingMs: timing,
      technologies: tech,
      detected: tech.length,
      server: headers['server'] || headers['x-powered-by'] || null,
      truncated: !!error && body.length > 0,
    }, null, 2) }],
  };
});

server.registerTool('security_headers', {
  description: 'Check security HTTP headers for a URL. Returns a security score, which headers are present (HSTS, CSP, X-Frame-Options, etc.) and which are missing. Essential for website security auditing.',
  inputSchema: z.object({
    url: z.string().describe('Full URL to check (e.g. https://example.com)'),
  }),
}, async ({ url }) => {
  const { statusCode, headers, body, error, timing } = await fetchUrl(url);
  const security = checkSecurityHeaders(headers);
  return {
    content: [{ type: 'text', text: JSON.stringify({
      url, statusCode, timingMs: timing,
      error: error && !body ? error : undefined,
      securityScore: security.score,
      present: security.present,
      missing: security.missing,
    }, null, 2) }],
  };
});

server.registerTool('email_security', {
  description: 'Check email security configuration for a domain. Returns SPF, DKIM, and DMARC record status. Essential for verifying deliverability and preventing email spoofing.',
  inputSchema: z.object({
    domain: z.string().describe('Domain to check (e.g. example.com)'),
  }),
}, async ({ domain }) => {
  const records = await resolveDns(domain);
  const email = checkEmailSecurity(records);
  return {
    content: [{ type: 'text', text: JSON.stringify({
      domain,
      spf: email.spf.present ? { status: 'configured', record: email.spf.record } : { status: 'not configured' },
      dmarc: email.dmarc.present ? { status: 'configured', record: email.dmarc.record } : { status: 'not configured' },
      emailProvider: email.dkim.domains?.[0] || 'Unknown',
      mxRecords: email.mxRecords,
    }, null, 2) }],
  };
});

server.registerTool('website_analyze', {
  description: 'Comprehensive website analysis. Given any URL, returns tech stack, hosting provider, security posture, SSL status, email security config, SEO metadata, social media profiles, WHOIS domain info, and DNS records. All from standard HTTP/DNS/WHOIS protocols — no scraping.',
  inputSchema: z.object({
    url: z.string().describe('Full URL to analyze (e.g. https://example.com)'),
  }),
}, async ({ url }) => {
  const parsed = new URL(url);
  const domain = parsed.hostname;

  const [fetchResult, dnsRecords, sslResult, whoisText] = await Promise.all([
    fetchUrl(url),
    resolveDns(domain),
    checkSsl(domain).catch(() => ({ valid: false, expired: false, error: 'SSL check failed' })),
    whoisLookup(domain).catch(() => 'WHOIS lookup failed'),
  ]);

  const { statusCode, headers, body, error, timing } = fetchResult;
  const tech = body ? detectTech(headers, body) : [];
  const security = checkSecurityHeaders(headers);
  const email = checkEmailSecurity(dnsRecords);
  const seo = body ? extractSeoMeta(headers, body) : {};
  const social = body ? extractSocialLinks(body) : {};
  const registrar = extractRegistrarInfo(whoisText);

  return {
    content: [{ type: 'text', text: JSON.stringify({
      url, domain,
      analysis: {
        httpStatus: { code: statusCode, timingMs: timing, truncated: !!error && body.length > 0 },
        technologies: { count: tech.length, items: tech },
        hosting: { server: headers['server'] || headers['x-powered-by'] || null },
        security: {
          score: security.score,
          headersPresent: security.present,
          headersMissing: security.missing,
          ssl: sslResult,
        },
        email: {
          provider: email.dkim.domains?.[0] || null,
          spf: email.spf.present ? 'configured' : 'not configured',
          dmarc: email.dmarc.present ? 'configured' : 'not configured',
          mxRecords: email.mxRecords,
        },
        seo: seo,
        social: social,
        domain: registrar,
        dns: Object.fromEntries(
          Object.entries(dnsRecords).filter(([_, v]) => (v as string[]).length > 0)
        ),
      },
    }, null, 2) }],
  };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(() => process.exit(1));

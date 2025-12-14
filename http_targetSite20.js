// internal_http_server.js (http.js)
// SHA-256（改行バリアント対応）でインライン許可 / 上流は常に HTTPS
// /_dev は 127.0.0.1:<port> へプロキシ。失敗時は 200 のスタブJSを返す（テスト用）
// Trusted Types は Report-Only 観測のまま
import http from 'http';
import https from 'https';
import zlib from 'zlib';
import dns from 'dns';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { generateCSP } from './csp-generator.mjs';

const gunzip = promisify(zlib.gunzip);
const brotliDecompress = zlib.brotliDecompress ? promisify(zlib.brotliDecompress) : null;

const ADD_REPORT_ONLY = true;
const MODE = 'compat';               // 互換モード（SHA + unsafe-hashes 等）
const REPORT_ONLY_STYLE = 'monitor'; // TT は Report-Only で観測

const LOCAL_ROOT = '/home/naoki/proxy-server/test/targetSite';
const LOCAL_FILES = {
    1: 'targetSite1.html', 2: 'targetSite2.html', 3: 'targetSite3.html', 4: 'targetSite4.html',
    5: 'targetSite5.html', 6: 'targetSite6.html', 7: 'targetSite7.html', 8: 'targetSite8.html',
    9: 'targetSite9.html', 10: 'targetSite10.html', 11: 'targetSite11.html', 12: 'targetSite12.html',
    13: 'targetSite13.html', 14: 'targetSite14.html', 15: 'targetSite15.html', 16: 'targetSite16.html',
    17: 'targetSite17.html', 18: 'targetSite18.html', 19: 'targetSite19.html', 20: 'targetSite20.html'
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ========== ユーティリティ ========== */
function normalizeHostParts(url) { return { normalizedHostname: (url.hostname || '').replace(/\.$/, ''), normalizedHost: (url.host || '').replace(/\.$/, '') }; }
function sanitizeReqHeaders(h) { const o = { ...h }; delete o['proxy-connection']; delete o['connection']; delete o['keep-alive']; delete o['te']; delete o['trailer']; delete o['upgrade']; delete o['expect']; Object.keys(o).forEach(k => { if (typeof o[k] === 'undefined') delete o[k]; }); return o; }
function sanitizeResHeaders(h) { const o = { ...h }; delete o['proxy-connection']; delete o['connection']; delete o['keep-alive']; delete o['te']; delete o['trailer']; delete o['upgrade']; if (typeof o['transfer-encoding'] === 'string' && o['transfer-encoding'] !== '') delete o['content-length']; return o; }
async function maybeDecodeBody(raw, enc) { if (!enc) return raw; try { const e = String(enc).toLowerCase(); if (e.includes('gzip')) return await gunzip(raw); if (e.includes('br') && brotliDecompress) return await brotliDecompress(raw); return raw; } catch { return raw; } }
function sha256b64(s) { return crypto.createHash('sha256').update(s, 'utf8').digest('base64'); }
function hashVariants(code) { return [sha256b64(code), sha256b64(code + '\n'), sha256b64(code + '\r\n')]; }
function isBlockedHost(h) { return /^(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+)$/.test(h); }

/* ========== スタブWAV ========== */
function makeSilentWav(durationMs = 250, sampleRate = 8000) { const nC = 1, bps = 8, bpS = bps / 8; const nS = Math.max(1, Math.floor(sampleRate * (durationMs / 1000))); const s2 = nS * nC * bpS; const cS = 36 + s2; const buf = Buffer.alloc(44 + s2); buf.write('RIFF', 0); buf.writeUInt32LE(cS, 4); buf.write('WAVE', 8); buf.write('fmt ', 12); buf.writeUInt32LE(16, 16); buf.writeUInt16LE(1, 20); buf.writeUInt16LE(nC, 22); buf.writeUInt32LE(sampleRate, 24); buf.writeUInt32LE(sampleRate * nC * bpS, 28); buf.writeUInt16LE(nC * bpS, 32); buf.writeUInt16LE(bps, 34); buf.write('data', 36); buf.writeUInt32LE(s2, 40); buf.fill(0x80, 44); return buf; }

/* ========== CSP ヘルパ ========== */
function withUpgradeInsecureRequests(h) { if (!h) return h; return /(^|;)\s*upgrade-insecure-requests(\s*;|$)/i.test(h) ? h : `${h.trim().replace(/;?$/, '')}; upgrade-insecure-requests`; }
function withScriptHashes(h, hashes) { if (!h || !hashes?.length) return h; const t = hashes.map(x => `'sha256-${x}'`).join(' '); return h.replace(/(script-src[^;]*)(;|$)/i, (m, g1, g2) => `${g1} ${t}${g2}`) || `${h}; script-src ${t}`; }
function buildFallbackCSP(inlineHashes) {
    const t = (inlineHashes || []).map(x => `'sha256-${x}'`).join(' '); return [
        `default-src 'self'`,
        `script-src 'self' https: 'strict-dynamic' ${t}`.trim(),
        `style-src 'self' 'unsafe-inline' https:`,
        `img-src 'self' data: blob: https:`,
        `media-src 'self' data: blob: https:`,
        `font-src 'self' data: https:`,
        `frame-src 'self'`,
        `object-src 'self'`,
        `connect-src 'self' https:`,
        `worker-src 'self' blob:`,
        `upgrade-insecure-requests`,
        `report-uri /csp-report`
    ].join('; ');
}

/* ========== 固定インライン（ASCII・末尾改行なし） ========== */
// securitypolicyviolation ダミー
const INLINE_VIOLATION_LOGGER =
    `window.securitypolicyviolation||(window.securitypolicyviolation=function(p){try{console.log('[CSP-violation]',p)}catch(_){}});`;
// fetch シム（クロス→/_proxy、http→https昇格）
const INLINE_FETCH_SHIM =
    `if(!window.__cspProxyShimInstalled){window.__cspProxyShimInstalled=1;var f=window.fetch;window.fetch=function(i,n){try{var s=typeof i==='string'?i:(i&&i.url)||'',u=new URL(s,location.href),a=/^https?:$/i.test(u.protocol)&&u.origin!==location.origin;if(a){var up=u.protocol==='http:'?'https:'+u.href.slice(5):u.href;return f('/_proxy?u='+encodeURIComponent(up),n)}}catch(_){ }return f(i,n)}}`;
// 括弧を使わない最小ローダ（IIFE廃止）
function makeInlineDevLoader(port, restPath) {
    const safeRest = String(restPath).replace(/'/g, "\\'");
    return `var d=document,s=d.createElement('script');s.src='/_dev/${port}/${safeRest}';(d.head||d.documentElement).appendChild(s);`;
}

/* ========== HTML 書換 + インライン挿入 ========== */
function rewriteLocalScriptsToInlineLoaders(html, out) {
    html = html.replace(
        /<script\b[^>]*\bsrc\s*=\s*(['"])(https?:\/\/)(localhost|127\.0\.0\.1)(?::(\d{2,5}))\/([^'"]+)\1[^>]*>\s*<\/script>/gi,
        (_m, _q, _proto, _h, port, rest) => { const code = makeInlineDevLoader(port, rest); out.push(code); return `<script>${code}</script>`; }
    );
    html = html.replace(
        /<script\b[^>]*\bsrc\s*=\s*(['"])\/_dev\/(\d{2,5})\/([^'"]+)\1[^>]*>\s*<\/script>/gi,
        (_m, _q, port, rest) => { const code = makeInlineDevLoader(port, rest); out.push(code); return `<script>${code}</script>`; }
    );
    return html;
}

function injectInlineHelpers(html, inlineHashesOut) {
    if (/<head[^>]*>/i.test(html) && !/<base\b[^>]*>/i.test(html)) {
        html = html.replace(/<head([^>]*)>/i, `<head$1><base href="/_localfs/">`);
    }
    const snippets = [];
    html = rewriteLocalScriptsToInlineLoaders(html, snippets);
    snippets.unshift(INLINE_FETCH_SHIM);
    snippets.unshift(INLINE_VIOLATION_LOGGER);

    const bundle = snippets.map(c => `<script>${c}</script>`).join('');
    if (/<\/head>/i.test(html)) html = html.replace(/<\/head>/i, bundle + '</head>');
    else if (/<body[^>]*>/i.test(html)) html = html.replace(/<body([^>]*)>/i, `<body$1>${bundle}`);
    else html = bundle + html;

    for (const c of snippets) { for (const h of hashVariants(c)) inlineHashesOut.push(h); }
    return html;
}

/* ========== /_proxy（HTTPSのみ・IPv4優先・example.com 救済） ========== */
async function handleProxyRequest(req, res, targetUrl) {
    let u; try { u = new URL(targetUrl); } catch { res.writeHead(400); res.end('Bad Request: invalid URL'); return; }
    if (u.protocol !== 'https:') { res.writeHead(400); res.end('Only https scheme is allowed'); return; }
    if (isBlockedHost(u.hostname)) { res.writeHead(403); res.end('Forbidden host'); return; }

    const baseHeaders = sanitizeReqHeaders(req.headers || {});
    baseHeaders.host = u.host; baseHeaders.connection = 'close';
    if (!baseHeaders['accept-encoding']) baseHeaders['accept-encoding'] = 'identity';
    if (!baseHeaders['user-agent']) baseHeaders['user-agent'] = 'NodeProxy/1.0';

    const perform = (urlObj, lookupFn, redirects = 5) => new Promise(resolve => {
        const opts = { hostname: urlObj.hostname, port: urlObj.port ? Number(urlObj.port) : 443, path: urlObj.pathname + (urlObj.search || ''), method: 'GET', headers: baseHeaders, servername: urlObj.hostname, ALPNProtocols: ['http/1.1'], insecureHTTPParser: true, lookup: lookupFn, timeout: 8000 };
        const up = https.request(opts, (upRes) => {
            if (upRes.statusCode >= 300 && upRes.statusCode < 400 && upRes.headers.location && redirects > 0) {
                try { const next = new URL(upRes.headers.location, urlObj); if (next.protocol !== 'https:') { upRes.resume(); return resolve({ error: Object.assign(new Error('non-HTTPS redirect'), { code: 'NON_HTTPS_REDIRECT' }) }); } upRes.resume(); return resolve(perform(next, lookupFn, redirects - 1)); } catch (e) { upRes.resume(); return resolve({ error: e }); }
            }
            const out = sanitizeResHeaders(upRes.headers || {}); out['cache-control'] = 'no-store';
            res.writeHead(upRes.statusCode || 200, out); upRes.pipe(res);
            upRes.on('end', () => resolve({ ok: true })); upRes.on('close', () => resolve({ ok: true }));
        });
        up.on('timeout', () => up.destroy(new Error('timeout')));
        up.on('error', err => resolve({ error: err }));
        up.end();
    });

    const v4 = (host, _o, cb) => dns.lookup(host, { family: 4 }, cb);
    const once = async (urlObj) => {
        let r = await perform(urlObj, v4, 5);
        const retryable = ['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'ESERVFAIL', 'ENOTFOUND', 'EAI_AGAIN', 'NON_HTTPS_REDIRECT'];
        if (r && r.error && urlObj.hostname === 'example.com' && retryable.includes(r.error.code || '')) {
            const alt = new URL(urlObj.href); alt.hostname = 'www.example.com';
            console.warn(`[_proxy] retry ${urlObj.hostname} -> ${alt.hostname}`);
            r = await perform(alt, v4, 5);
        }
        return r;
    };
    const r = await once(u);
    if (r && r.error) { console.error('[_proxy] error:', (r.error.code || r.error.message), u.href); try { res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' }); res.end('Bad Gateway (_proxy)'); } catch { } }
}

/* ========== Local HTML + CSP（フォールバック付き） ========== */
async function serveLocalHTML(res, url, filePath) {
    const tag = `[serveLocalHTML ${url}]`;
    try {
        if (!fs.existsSync(filePath)) { console.error(tag, 'not found:', filePath); res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }); res.end(`Not found: ${filePath}`); return; }
        let html = fs.readFileSync(filePath, 'utf8');
        const inlineHashes = []; html = injectInlineHelpers(html, inlineHashes);

        let enforceHeader, reportOnlyHeader;
        try {
            const out = await generateCSP(url, html, { mode: MODE, addReportOnly: ADD_REPORT_ONLY, reportOnlyStyle: REPORT_ONLY_STYLE, reportUri: '/csp-report' });
            enforceHeader = out.enforceHeader; reportOnlyHeader = out.reportOnlyHeader;
        } catch (e) {
            console.error(tag, 'generateCSP failed:', e && e.stack || e);
            enforceHeader = buildFallbackCSP(inlineHashes); reportOnlyHeader = '';
        }
        enforceHeader = withUpgradeInsecureRequests(withScriptHashes(enforceHeader, inlineHashes)) || buildFallbackCSP(inlineHashes);
        if (reportOnlyHeader) reportOnlyHeader = withUpgradeInsecureRequests(withScriptHashes(reportOnlyHeader, inlineHashes));

        const headers = { 'content-type': 'text/html; charset=utf-8', 'content-length': String(Buffer.byteLength(html, 'utf8')), 'content-security-policy': enforceHeader };
        if (reportOnlyHeader) headers['content-security-policy-report-only'] = reportOnlyHeader;
        res.writeHead(200, headers); res.end(html);
    } catch (e) {
        console.error(tag, 'fatal:', e && e.stack || e);
        const body = '<!doctype html><meta charset="utf-8"><title>local test fallback</title><h1>local test fallback</h1>';
        const fb = buildFallbackCSP([]); res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': String(Buffer.byteLength(body, 'utf8')), 'content-security-policy': fb }); res.end(body);
    }
}

/* ========== /_dev （localhost 任意ポート → 127.0.0.1:<port>） ========== */
// 失敗時は 200 のスタブJSを返す（502 を出さないテスト用）
function proxyToDevPort(req, res, port, targetPath) {
    const devHost = '127.0.0.1';
    const devPort = Number(port) || 1234; // 既定 1234
    const headers = sanitizeReqHeaders(req.headers || {});
    headers.host = `${devHost}:${devPort}`;
    headers.connection = 'close';
    if (!headers['accept-encoding']) headers['accept-encoding'] = 'identity';

    const opts = { hostname: devHost, port: devPort, path: targetPath, method: (req.method || 'GET').toUpperCase(), headers, timeout: 3000 };
    const devReq = http.request(opts, (devRes) => { const out = sanitizeResHeaders(devRes.headers || {}); res.writeHead(devRes.statusCode || 200, out); devRes.pipe(res); });

    const sendStub = (why) => { console.warn('[/ _dev fallback] return stub JS:', why); const js = `/* dev fallback */\nconsole.log('[DEV STUB] ${devHost}:${devPort}${targetPath}');`; const buf = Buffer.from(js, 'utf8'); res.writeHead(200, { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'no-store', 'content-length': String(buf.byteLength) }); res.end(buf); };

    devReq.on('timeout', () => devReq.destroy(new Error('timeout')));
    devReq.on('error', (err) => sendStub(err.code || err.message));
    req.pipe(devReq);
}

/* ========== Main HTTP server ========== */
http.createServer((req, res) => {
    const isTLS = !!req.socket.encrypted; const scheme = isTLS ? 'https' : 'http';
    const raw = req.url && req.url.startsWith('http') ? req.url : `${scheme}://${req.headers.host}${req.url}`;
    let targetUrl; try { targetUrl = new URL(raw); } catch { res.writeHead(400); res.end('Bad Request'); return; }
    const { normalizedHostname, normalizedHost } = normalizeHostParts(targetUrl);

    if (targetUrl.pathname === '/favicon.ico') { res.writeHead(204, { 'content-type': 'image/x-icon' }); res.end(); return; }
    if (targetUrl.pathname === '/csp-report') { let b = []; req.on('data', c => b.push(c)); req.on('end', () => { try { console.log('[CSP-REPORT]', Buffer.concat(b).toString('utf8')); } catch { } res.writeHead(204); res.end(); }); return; }

    // HTTPS only リレー
    if (targetUrl.pathname === '/._proxy' || targetUrl.pathname === '/_proxy') { const u = targetUrl.searchParams.get('u') || ''; handleProxyRequest(req, res, u); return; }

    // /_dev プロキシ（:port 明示 or 既定1234）
    if (targetUrl.pathname === '/._dev' || targetUrl.pathname === '/_dev') { proxyToDevPort(req, res, 1234, targetUrl.search || '/'); return; }
    if (targetUrl.pathname.startsWith('/_dev/')) { const rest = targetUrl.pathname.replace(/^\/_dev\//, ''); const m = rest.match(/^(\d{2,5})(\/.*)?$/); if (!m) { res.writeHead(400); res.end('Bad Request (/ _dev)'); return; } const port = m[1]; const after = m[2] || '/'; const full = after + (targetUrl.search || ''); proxyToDevPort(req, res, port, full); return; }

    // not-example.com スタブ
    if (normalizedHostname === 'not-example.com') {
        if (/^\/audio(?:\/|$)/.test(targetUrl.pathname)) { const wav = makeSilentWav(); res.writeHead(200, { 'content-type': 'audio/wav', 'content-length': String(wav.byteLength), 'cache-control': 'no-store', 'accept-ranges': 'bytes' }); res.end(wav); return; }
        if (/^\/flash(?:\/|$)/.test(targetUrl.pathname)) { const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="180"><rect width="100%" height="100%" fill="#ff9800"/><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="sans-serif" font-size="18" fill="#fff">fake SWF content</text></svg>`; const buf = Buffer.from(svg, 'utf8'); res.writeHead(200, { 'content-type': 'image/svg+xml; charset=utf-8', 'content-length': String(buf.byteLength), 'cache-control': 'no-store' }); res.end(buf); return; }
        if (/^\/styles\/.+\.css$/i.test(targetUrl.pathname)) { const css = `body{margin:16px;}h1{font-family:system-ui,sans-serif;font-weight:700}h1::after{content:" (from not-example.com CSS)"}`; const buf = Buffer.from(css, 'utf8'); res.writeHead(200, { 'content-type': 'text/css; charset=utf-8', 'content-length': String(buf.byteLength), 'cache-control': 'no-store' }); res.end(buf); return; }
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="120"><rect width="100%" height="100%" fill="#4caf50"/><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="sans-serif" font-size="16" fill="#fff">stub image</text></svg>`; const buf = Buffer.from(svg, 'utf8'); res.writeHead(200, { 'content-type': 'image/svg+xml; charset=utf-8', 'content-length': String(buf.byteLength), 'cache-control': 'no-store' }); res.end(buf); return;
    }

    // /_localfs/
    if (targetUrl.pathname.startsWith('/_localfs/')) {
        const rel = targetUrl.pathname.replace(/^\/_localfs\//, ''); const abs = path.join(LOCAL_ROOT, rel);
        const resolved = path.resolve(abs), rootRes = path.resolve(LOCAL_ROOT);
        if (!resolved.startsWith(rootRes + path.sep) && resolved !== rootRes) { res.writeHead(403); res.end('Forbidden'); return; }
        fs.readFile(resolved, (err, buf) => { if (err) { res.writeHead(404); res.end('Not found'); return; } const ext = path.extname(resolved).toLowerCase(); const ct = ext === '.js' || ext === '.mjs' ? 'application/javascript' : ext === '.css' ? 'text/css; charset=utf-8' : ext === '.html' ? 'text/html; charset=utf-8' : ext === '.png' ? 'image/png' : (ext === '.jpg' || ext === '.jpeg') ? 'image/jpeg' : ext === '.gif' ? 'image/gif' : ext === '.svg' ? 'image/svg+xml' : ext === '.mp3' ? 'audio/mpeg' : ext === '.wav' ? 'audio/wav' : ext === '.ogg' ? 'audio/ogg' : 'application/octet-stream'; res.writeHead(200, { 'content-type': ct, 'content-length': String(buf.byteLength) }); res.end(buf); }); return;
    }

    // /_local_test1..20
    for (let i = 1; i <= 20; i++) { if (targetUrl.pathname === `/_local_test${i}`) { const file = path.join(LOCAL_ROOT, LOCAL_FILES[i]); serveLocalHTML(res, targetUrl.href, file); return; } }

    // ===== 上流MITM（HTMLのみ CSP 付与）— 常に HTTPS:443 =====
    const fwdHeaders = sanitizeReqHeaders(req.headers || {}); fwdHeaders.host = normalizedHost || targetUrl.host; fwdHeaders.connection = 'close'; if (!fwdHeaders['accept-encoding']) fwdHeaders['accept-encoding'] = 'identity';

    const upstream = https.request({ hostname: normalizedHostname, port: 443, path: targetUrl.pathname + (targetUrl.search || ''), method: (req.method || 'GET').toUpperCase(), headers: fwdHeaders, servername: normalizedHostname, ALPNProtocols: ['http/1.1'], insecureHTTPParser: true }, (proxyRes) => {
        const ct = String(proxyRes.headers['content-type'] || '').toLowerCase(); const isHtml = ct.includes('text/html');
        if (!isHtml) { const out = sanitizeResHeaders(proxyRes.headers || {}); res.writeHead(proxyRes.statusCode || 200, out); proxyRes.pipe(res); return; }
        const chunks = []; proxyRes.on('data', c => chunks.push(c)); proxyRes.on('end', async () => {
            try {
                const raw = Buffer.concat(chunks); const dec = await maybeDecodeBody(raw, proxyRes.headers['content-encoding']); let html = dec.toString('utf8');
                const inlineHashes = []; html = injectInlineHelpers(html, inlineHashes);

                let { enforceHeader, reportOnlyHeader } = await generateCSP(targetUrl.href, html, { mode: MODE, addReportOnly: ADD_REPORT_ONLY, reportOnlyStyle: REPORT_ONLY_STYLE, reportUri: '/csp-report' });
                enforceHeader = withUpgradeInsecureRequests(withScriptHashes(enforceHeader, inlineHashes));
                if (reportOnlyHeader) reportOnlyHeader = withUpgradeInsecureRequests(withScriptHashes(reportOnlyHeader, inlineHashes));

                const out = sanitizeResHeaders(proxyRes.headers || {}); delete out['content-security-policy']; delete out['content-security-policy-report-only']; delete out['content-encoding']; delete out['transfer-encoding'];
                const body = Buffer.from(html, 'utf8'); out['content-length'] = String(body.byteLength); out['content-security-policy'] = enforceHeader; if (reportOnlyHeader) out['content-security-policy-report-only'] = reportOnlyHeader;
                res.writeHead(proxyRes.statusCode || 200, out); res.end(body);
            } catch (e) { console.error('[HTTP] CSP generation error:', e && e.stack || e); const out = sanitizeResHeaders(proxyRes.headers || {}); try { res.writeHead(proxyRes.statusCode || 502, out); res.end(Buffer.concat(chunks)); } catch { } }
        });
    });
    upstream.on('error', err => { console.error('[HTTP] Error forwarding request:', err); try { res.writeHead(502); res.end('Bad Gateway'); } catch { } });
    req.pipe(upstream);
}).listen(8080, '0.0.0.0', () => {
    console.log('[INIT] LOCAL_ROOT =', LOCAL_ROOT);
    console.log('[INIT] LOCAL_FILES[20] =', LOCAL_FILES[20]);
    console.log('Internal HTTP server on 8080 (SHA256 hashes w/ newline variants, fallback CSP, upstream HTTPS fixed). _local_test1..20 ready; /_dev/<port> -> 127.0.0.1:<port> (fallback stub)');
});

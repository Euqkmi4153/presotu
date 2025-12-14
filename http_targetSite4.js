// internal_http_server.js (http.js) — CSPは csp-generator.mjs で自動構成
// 上流HTTPS固定 / HTMLのみCSP付与 / ダミー関数は常に挿入
import http from 'http';
import https from 'https';
import zlib from 'zlib';
import dns from 'dns';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { generateCSP } from './csp-generator.mjs';

const gunzip = promisify(zlib.gunzip);
const brotliDecompress = zlib.brotliDecompress ? promisify(zlib.brotliDecompress) : null;

const ADD_REPORT_ONLY = true;
const MODE = 'compat';
const REPORT_ONLY_STYLE = 'monitor';
const REPORT_URI = '/csp-report';

const LOCAL_ROOT = '/home/naoki/proxy-server/test/targetSite';
const LOCAL_FILES = {
    1: 'targetSite1.html',
    2: 'targetSite2.html',
    3: 'targetSite3.html',
    4: 'targetSite4.html',
    5: 'targetSite5.html',
    6: 'targetSite6.html',
    7: 'targetSite7.html',
    8: 'targetSite8.html',
    9: 'targetSite9.html',
    10: 'targetSite10.html',
    11: 'targetSite11.html',
    12: 'targetSite12.html',
    13: 'targetSite13.html',
    14: 'targetSite14.html',
    15: 'targetSite15.html',
    16: 'targetSite16.html',
    17: 'targetSite17.html',
    18: 'targetSite18.html',
    19: 'targetSite19.html',
    20: 'targetSite20.html',
    21: 'targetSite21.html',
    22: 'targetSite22.html',
    23: 'targetSite23.html',
    24: 'targetSite24.html',
    25: 'targetSite25.html',
    26: 'targetSite26.html',
    27: 'targetSite27.html',
    28: 'targetSite28.html',
    29: 'targetSite29.html',
    30: 'targetSite30.html',
    31: 'targetSite31.html',
    32: 'targetSite32.html',
    33: 'targetSite33.html',
    34: 'targetSite34.html',
    35: 'targetSite35.html',
    36: 'targetSite36.html',
    37: 'targetSite37.html',
    38: 'targetSite38.html',
    39: 'targetSite39.html',
    40: 'targetSite40.html',
    41: 'targetSite41.html',
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ---------- utils ---------- */
function normalizeHostParts(url) {
    return {
        normalizedHostname: (url.hostname || '').replace(/\.$/, ''),
        normalizedHost: (url.host || '').replace(/\.$/, '')
    };
}
function sanitizeReqHeaders(h) {
    const o = { ...h };
    delete o['proxy-connection']; delete o['connection']; delete o['keep-alive'];
    delete o['te']; delete o['trailer']; delete o['upgrade']; delete o['expect'];
    Object.keys(o).forEach(k => { if (typeof o[k] === 'undefined') delete o[k]; });
    return o;
}
function sanitizeResHeaders(h) {
    const o = { ...h };
    delete o['proxy-connection']; delete o['connection']; delete o['keep-alive'];
    delete o['te']; delete o['trailer']; delete o['upgrade'];
    if (typeof o['transfer-encoding'] === 'string' && o['transfer-encoding'] !== '') delete o['content-length'];
    return o;
}
async function maybeDecodeBody(raw, enc) {
    if (!enc) return raw;
    try {
        const e = String(enc).toLowerCase();
        if (e.includes('gzip')) return await gunzip(raw);
        if (e.includes('br') && brotliDecompress) return await brotliDecompress(raw);
        return raw;
    } catch { return raw; }
}

/* ---------- HTML helpers ---------- */
/**
 * addBaseForLocal = true のときだけ <base href="/_localfs/"> を挿入する。
 * 上流サイト（https://www.kansai-u.ac.jp/... など）には base を入れない。
 */
function injectHelpers(html, { addBaseForLocal = false } = {}) {
    // base（相対参照安定）— ローカルテストページのみ
    if (addBaseForLocal && /<head[^>]*>/i.test(html) && !/<base\b[^>]*>/i.test(html)) {
        html = html.replace(/<head([^>]*)>/i, `<head$1><base href="/_localfs/">`);
    }
    // securitypolicyviolation ダミー（常に用意・既存は上書きしない）
    const helper = `<script>window.securitypolicyviolation||(window.securitypolicyviolation=function(p){try{console.log('[CSP-violation]',p)}catch(_){}});</script>`;
    if (/<\/head>/i.test(html)) {
        html = html.replace(/<\/head>/i, helper + '</head>');
    } else if (/<body[^>]*>/i.test(html)) {
        html = html.replace(/<body([^>]*)>/i, `<body$1>${helper}`);
    } else {
        html = helper + html;
    }
    return html;
}

// enforce 用にだけ upgrade-insecure-requests を足す
function appendUpgradeInsecureRequests(csp) {
    if (!csp) return csp;
    return /(?:^|;\s*)upgrade-insecure-requests(?:\s*;|$)/i.test(csp)
        ? csp
        : `${csp.trim().replace(/;?$/, '')}; upgrade-insecure-requests`;
}

/* ---------- /_proxy（httpsのみ） ---------- */
async function handleProxyRequest(req, res, targetUrl) {
    let u;
    try { u = new URL(targetUrl); } catch { res.writeHead(400); res.end('Bad Request: invalid URL'); return; }
    if (u.protocol !== 'https:') { res.writeHead(400); res.end('Only https scheme is allowed'); return; }

    const baseHeaders = sanitizeReqHeaders(req.headers || {});
    baseHeaders.host = u.host;
    baseHeaders.connection = 'close';
    if (!baseHeaders['accept-encoding']) baseHeaders['accept-encoding'] = 'identity';
    if (!baseHeaders['user-agent']) baseHeaders['user-agent'] = 'NodeProxy/1.0';

    const perform = (urlObj, lookupFn, redirects = 5) => new Promise(resolve => {
        const opts = {
            hostname: urlObj.hostname,
            port: urlObj.port ? Number(urlObj.port) : 443,
            path: urlObj.pathname + (urlObj.search || ''),
            method: 'GET',
            headers: baseHeaders,
            servername: urlObj.hostname,
            ALPNProtocols: ['http/1.1'],
            insecureHTTPParser: true,
            lookup: lookupFn,
            timeout: 8000
        };
        const up = https.request(opts, (upRes) => {
            if (upRes.statusCode >= 300 && upRes.statusCode < 400 && upRes.headers.location && redirects > 0) {
                try {
                    const next = new URL(upRes.headers.location, urlObj);
                    if (next.protocol !== 'https:') { upRes.resume(); return resolve({ error: new Error('non-HTTPS redirect') }); }
                    upRes.resume(); return resolve(perform(next, lookupFn, redirects - 1));
                } catch (e) { upRes.resume(); return resolve({ error: e }); }
            }
            const out = sanitizeResHeaders(upRes.headers || {});
            out['cache-control'] = 'no-store';
            res.writeHead(upRes.statusCode || 200, out);
            upRes.pipe(res);
            upRes.on('end', () => resolve({ ok: true }));
            upRes.on('close', () => resolve({ ok: true }));
        });
        up.on('timeout', () => up.destroy(new Error('timeout')));
        up.on('error', err => resolve({ error: err }));
        up.end();
    });

    const v4 = (host, _o, cb) => dns.lookup(host, { family: 4 }, cb);
    const r = await perform(u, v4, 5);
    if (r && r.error) {
        try {
            if (u.hostname === 'example.com') {
                const alt = new URL(u.href);
                alt.hostname = 'www.example.com';
                const r2 = await perform(alt, v4, 5);
                if (!(r2 && r2.ok)) throw new Error('fallback failed');
                return;
            }
        } catch { }
        console.error('[_proxy] error:', r.error.message || r.error);
        try {
            res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
            res.end('Bad Gateway (_proxy)');
        } catch { }
    }
}

/* ---------- Local HTML + 自動CSP ---------- */
async function serveLocalHTML(res, url, filePath) {
    try {
        const htmlRaw = fs.readFileSync(filePath, 'utf8');
        // ★ ローカルテストページなので base を挿入する
        const html = injectHelpers(htmlRaw, { addBaseForLocal: true });

        const { enforceHeader, reportOnlyHeader } =
            await generateCSP(url, html, {
                mode: MODE,
                addReportOnly: ADD_REPORT_ONLY,
                reportOnlyStyle: REPORT_ONLY_STYLE,
                reportUri: REPORT_URI
            });

        const enforceCsp = appendUpgradeInsecureRequests(enforceHeader || '');

        const headers = {
            'content-type': 'text/html; charset=utf-8',
            'content-length': String(Buffer.byteLength(html, 'utf8')),
            'content-security-policy': enforceCsp
        };
        // ★ Report-Only には upgrade-insecure-requests を付けない（警告回避）
        if (reportOnlyHeader) {
            headers['content-security-policy-report-only'] = reportOnlyHeader;
        }

        res.writeHead(200, headers);
        res.end(html);
    } catch (e) {
        console.error('[serveLocalHTML] error:', e);
        res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('local test error');
    }
}

/* ---------- /_dev（ローカル開発フォワード；失敗時は STUB JS） ---------- */
function proxyToDevPort(req, res, port, targetPath) {
    const devHost = '127.0.0.1';
    const devPort = Number(port) || 1234;
    const headers = sanitizeReqHeaders(req.headers || {});
    headers.host = `${devHost}:${devPort}`;
    headers.connection = 'close';
    if (!headers['accept-encoding']) headers['accept-encoding'] = 'identity';

    const opts = {
        hostname: devHost,
        port: devPort,
        path: targetPath,
        method: (req.method || 'GET').toUpperCase(),
        headers,
        timeout: 3000
    };
    const devReq = http.request(opts, (devRes) => {
        const out = sanitizeResHeaders(devRes.headers || {});
        res.writeHead(devRes.statusCode || 200, out);
        devRes.pipe(res);
    });

    const sendStub = (why) => {
        console.warn('[/ _dev fallback] return stub JS:', why);
        const js = `/* dev fallback */\nconsole.log('[DEV STUB] ${devHost}:${devPort}${targetPath}');`;
        const buf = Buffer.from(js, 'utf8');
        res.writeHead(200, {
            'content-type': 'application/javascript; charset=utf-8',
            'cache-control': 'no-store',
            'content-length': String(buf.byteLength)
        });
        res.end(buf);
    };

    devReq.on('timeout', () => devReq.destroy(new Error('timeout')));
    devReq.on('error', (err) => sendStub(err.code || err.message));
    req.pipe(devReq);
}

/* ---------- HTTP Server ---------- */
http.createServer((req, res) => {
    const isTLS = !!req.socket.encrypted;
    const scheme = isTLS ? 'https' : 'http';
    const raw = req.url && req.url.startsWith('http') ? req.url : `${scheme}://${req.headers.host}${req.url}`;
    let targetUrl;
    try { targetUrl = new URL(raw); } catch { res.writeHead(400); res.end('Bad Request'); return; }
    const { normalizedHostname, normalizedHost } = normalizeHostParts(targetUrl);

    if (targetUrl.pathname === '/favicon.ico') {
        res.writeHead(204, { 'content-type': 'image/x-icon' });
        res.end();
        return;
    }

    if (targetUrl.pathname === '/csp-report') {
        let body = [];
        req.on('data', c => body.push(c));
        req.on('end', () => {
            try { console.log('[CSP-REPORT]', Buffer.concat(body).toString('utf8')); } catch { }
            res.writeHead(204);
            res.end();
        });
        return;
    }

    // 内部API
    if (targetUrl.pathname === '/._proxy' || targetUrl.pathname === '/_proxy') {
        const u = targetUrl.searchParams.get('u') || '';
        handleProxyRequest(req, res, u);
        return;
    }
    if (targetUrl.pathname === '/._dev' || targetUrl.pathname === '/_dev') {
        proxyToDevPort(req, res, 1234, targetUrl.search || '/');
        return;
    }
    if (targetUrl.pathname.startsWith('/_dev/')) {
        const rest = targetUrl.pathname.replace(/^\/_dev\//, '');
        const m = rest.match(/^(\d{2,5})(\/.*)?$/);
        if (!m) { res.writeHead(400); res.end('Bad Request (/ _dev)'); return; }
        const port = m[1];
        const after = m[2] || '/';
        const full = after + (targetUrl.search || '');
        proxyToDevPort(req, res, port, full);
        return;
    }

    // not-example.com スタブ（CSS/音声/SVG/VIDEO/SUBTITLES）
    if (normalizedHostname === 'not-example.com') {
        // audio stub (small wav)
        if (/^\/audio(?:\/|$)/.test(targetUrl.pathname)) {
            const wav = Buffer.alloc(44, 0);
            res.writeHead(200, {
                'content-type': 'audio/wav',
                'cache-control': 'no-store',
                'access-control-allow-origin': '*'
            });
            res.end(wav);
            return;
        }
        // fake "flash" content as SVG
        if (/^\/flash(?:\/|$)/.test(targetUrl.pathname)) {
            const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="180"><rect width="100%" height="100%" fill="#ff9800"/><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="sans-serif" font-size="18" fill="#fff">fake SWF content</text></svg>`;
            const buf = Buffer.from(svg, 'utf8');
            res.writeHead(200, {
                'content-type': 'image/svg+xml; charset=utf-8',
                'content-length': String(buf.byteLength),
                'cache-control': 'no-store',
                'access-control-allow-origin': '*'
            });
            res.end(buf);
            return;
        }
        // CSS stub
        if (/^\/styles\/.+\.css$/i.test(targetUrl.pathname)) {
            const css = `body{margin:16px;}h1{font-family:system-ui,sans-serif;font-weight:700}h1::after{content:" (from not-example.com CSS)"}`;
            const buf = Buffer.from(css, 'utf8');
            res.writeHead(200, {
                'content-type': 'text/css; charset=utf-8',
                'content-length': String(buf.byteLength),
                'cache-control': 'no-store',
                'access-control-allow-origin': '*'
            });
            res.end(buf);
            return;
        }
        // video stub
        if (/^\/video(?:\/|$)/.test(targetUrl.pathname)) {
            const buf = Buffer.from('', 'utf8');
            res.writeHead(200, {
                'content-type': 'video/mp4',
                'content-length': String(buf.byteLength),
                'cache-control': 'no-store',
                'accept-ranges': 'none',
                'access-control-allow-origin': '*'
            });
            res.end(buf);
            return;
        }
        // subtitles (WebVTT)
        if (/^\/subtitles(?:\/|$)/.test(targetUrl.pathname)) {
            const vtt = `WEBVTT\n\n00:00:00.000 --> 00:00:02.000\nsample subtitle\n`;
            const buf = Buffer.from(vtt, 'utf8');
            res.writeHead(200, {
                'content-type': 'text/vtt; charset=utf-8',
                'content-length': String(buf.byteLength),
                'cache-control': 'no-store',
                'access-control-allow-origin': '*'
            });
            res.end(buf);
            return;
        }
        // default image/svg stub（ルート / やその他パス用）＋ CORS 許可
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="120"><rect width="100%" height="100%" fill="#4caf50"/><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="sans-serif" font-size="16" fill="#fff">stub image</text></svg>`;
        const buf = Buffer.from(svg, 'utf8');
        res.writeHead(200, {
            'content-type': 'image/svg+xml; charset=utf-8',
            'content-length': String(buf.byteLength),
            'cache-control': 'no-store',
            'access-control-allow-origin': '*'
        });
        res.end(buf);
        return;
    }

    // /_localfs/
    if (targetUrl.pathname.startsWith('/_localfs/')) {
        const rel = targetUrl.pathname.replace(/^\/_localfs\//, '');
        const abs = path.join(LOCAL_ROOT, rel);
        const resolved = path.resolve(abs), rootRes = path.resolve(LOCAL_ROOT);
        if (!resolved.startsWith(rootRes + path.sep) && resolved !== rootRes) {
            res.writeHead(403);
            res.end('Forbidden');
            return;
        }
        fs.readFile(resolved, (err, buf) => {
            if (err) {
                // 404 → <img src="1" onerror=...> 等のテストで onerror を確実に発火させる
                res.writeHead(404, {
                    'content-type': 'text/plain; charset=utf-8',
                    'cache-control': 'no-store'
                });
                res.end('Not found');
                return;
            }
            const ext = path.extname(resolved).toLowerCase();
            const ct = ext === '.js' || ext === '.mjs' ? 'application/javascript'
                : ext === '.css' ? 'text/css; charset=utf-8'
                    : ext === '.html' ? 'text/html; charset=utf-8'
                        : ext === '.png' ? 'image/png'
                            : (ext === '.jpg' || ext === '.jpeg') ? 'image/jpeg'
                                : ext === '.gif' ? 'image/gif'
                                    : ext === '.svg' ? 'image/svg+xml'
                                        : ext === '.mp3' ? 'audio/mpeg'
                                            : ext === '.wav' ? 'audio/wav'
                                                : ext === '.ogg' ? 'audio/ogg'
                                                    : 'application/octet-stream';
            res.writeHead(200, {
                'content-type': ct,
                'content-length': String(buf.byteLength)
            });
            res.end(buf);
        });
        return;
    }

    // /_local_test1..41
    for (let i = 1; i <= 41; i++) {
        if (targetUrl.pathname === `/_local_test${i}`) {
            const file = path.join(LOCAL_ROOT, LOCAL_FILES[i]);
            serveLocalHTML(res, targetUrl.href, file);
            return;
        }
    }

    /* ===== 上流MITM（HTMLのみCSP付与）— 常に HTTPS:443 ===== */
    const fwdHeaders = sanitizeReqHeaders(req.headers || {});
    fwdHeaders.host = normalizedHost || targetUrl.host;
    fwdHeaders.connection = 'close';
    if (!fwdHeaders['accept-encoding']) fwdHeaders['accept-encoding'] = 'identity';

    const upstream = https.request({
        hostname: normalizedHostname,
        port: 443,
        path: targetUrl.pathname + (targetUrl.search || ''),
        method: (req.method || 'GET').toUpperCase(),
        headers: fwdHeaders,
        servername: normalizedHostname,
        ALPNProtocols: ['http/1.1'],
        insecureHTTPParser: true,
    }, (proxyRes) => {
        const ct = String(proxyRes.headers['content-type'] || '').toLowerCase();
        const isHtml = ct.includes('text/html');
        if (!isHtml) {
            const out = sanitizeResHeaders(proxyRes.headers || {});

            res.writeHead(proxyRes.statusCode || 200, out);
            proxyRes.pipe(res);
            return;
        }

        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', async () => {
            try {
                const raw = Buffer.concat(chunks);
                const decoded = await maybeDecodeBody(raw, proxyRes.headers['content-encoding']);
                // ★ 上流HTMLには base を入れない（addBaseForLocal: false）
                const html = injectHelpers(decoded.toString('utf8'), { addBaseForLocal: false });

                const { enforceHeader, reportOnlyHeader } =
                    await generateCSP(targetUrl.href, html, {
                        mode: MODE,
                        addReportOnly: ADD_REPORT_ONLY,
                        reportOnlyStyle: REPORT_ONLY_STYLE,
                        reportUri: REPORT_URI
                    });

                const out = sanitizeResHeaders(proxyRes.headers || {});
                delete out['content-security-policy'];
                delete out['content-security-policy-report-only'];
                delete out['content-encoding'];
                delete out['transfer-encoding'];

                const body = Buffer.from(html, 'utf8');
                out['content-length'] = String(body.byteLength);

                // enforce だけ upgrade-insecure-requests を付与
                out['content-security-policy'] = appendUpgradeInsecureRequests(enforceHeader || '');
                // Report-Only 側はそのまま（ブラウザ警告を出さない）
                if (reportOnlyHeader) {
                    out['content-security-policy-report-only'] = reportOnlyHeader;
                }

                res.writeHead(proxyRes.statusCode || 200, out);
                res.end(body);
            } catch (e) {
                console.error('[HTTP] CSP generation error:', e);
                const out = sanitizeResHeaders(proxyRes.headers || {});
                try {
                    res.writeHead(proxyRes.statusCode || 502, out);
                    res.end(Buffer.concat(chunks));
                } catch { }
            }
        });
    });

    upstream.on('error', err => {
        console.error('[HTTP] Error forwarding request:', err);
        try {
            res.writeHead(502);
            res.end('Bad Gateway');
        } catch { }
    });
    req.pipe(upstream);
}).listen(8080, '0.0.0.0', () => {
    console.log('[INIT] LOCAL_ROOT =', LOCAL_ROOT);
    console.log('[INIT] ready _local_test1..41 ; upstream HTTPS fixed; CSP by csp-generator.mjs');
});

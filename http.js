// internal_http_server.js (ESM)
import http from 'http';
import https from 'https';
import zlib from 'zlib';
import { promisify } from 'util';
import { generateCSP } from './csp-generator.mjs';

const gunzip = promisify(zlib.gunzip);
const brotliDecompress = zlib.brotliDecompress ? promisify(zlib.brotliDecompress) : null;

// ===== 運用切替スイッチ =====
const ADD_REPORT_ONLY = true;       // 監視も同時に送りたい時は true（ページ/ホストで条件分岐してもOK）
const MODE = 'compat';              // 互換重視。必要に応じ 'nonce'

function normalizeHostParts(url) {
    return {
        normalizedHostname: url.hostname.replace(/\.$/, ''),
        normalizedHost: url.host.replace(/\.$/, '')
    };
}
function sanitizeReqHeaders(h) {
    const out = { ...h };
    delete out['proxy-connection']; delete out['connection'];
    delete out['keep-alive']; delete out['te'];
    delete out['trailer']; delete out['upgrade'];
    delete out['expect'];
    Object.keys(out).forEach(k => { if (typeof out[k] === 'undefined') delete out[k]; });
    return out;
}
function sanitizeResHeaders(h) {
    const out = { ...h };
    delete out['proxy-connection']; delete out['connection'];
    delete out['keep-alive']; delete out['te'];
    delete out['trailer']; delete out['upgrade'];
    return out;
}
async function maybeDecodeBody(raw, encoding) {
    if (!encoding) return raw;
    const enc = String(encoding).toLowerCase();
    try {
        if (enc.includes('gzip')) return await gunzip(raw);
        if (enc.includes('br') && brotliDecompress) return await brotliDecompress(raw);
        return raw;
    } catch { return raw; }
}

http.createServer((req, res) => {
    const rawUrl = req.url.startsWith('http') ? req.url : `https://${req.headers.host}${req.url}`;
    const targetUrl = new URL(rawUrl);
    const { normalizedHostname, normalizedHost } = normalizeHostParts(targetUrl);

    const fwdHeaders = sanitizeReqHeaders(req.headers || {});
    fwdHeaders.host = normalizedHost;
    fwdHeaders.connection = 'close';
    fwdHeaders['accept-encoding'] = fwdHeaders['accept-encoding'] || 'identity';

    const method = (req.method || 'GET').toUpperCase();
    const mayHaveBody = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
    const hasCL = typeof req.headers['content-length'] === 'string' && req.headers['content-length'] !== '';
    const hasTE = typeof req.headers['transfer-encoding'] === 'string' && req.headers['transfer-encoding'] !== '';
    if (mayHaveBody && !hasCL && !hasTE) fwdHeaders['transfer-encoding'] = 'chunked';

    const proxyOptions = {
        hostname: normalizedHostname,
        port: 443,
        path: targetUrl.pathname + targetUrl.search,
        method,
        headers: fwdHeaders,
        servername: normalizedHostname,
        ALPNProtocols: ['http/1.1'],
        insecureHTTPParser: true,
    };

    const proxyReq = https.request(proxyOptions, (proxyRes) => {
        const contentType = String(proxyRes.headers['content-type'] || '').toLowerCase();
        const isHtml = contentType.includes('text/html');

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
                const html = decoded.toString('utf8');

                const { enforceHeader, reportOnlyHeader } = await generateCSP(
                    targetUrl.href, html, { mode: MODE, addReportOnly: ADD_REPORT_ONLY }
                );

                const out = sanitizeResHeaders(proxyRes.headers || {});
                delete out['content-encoding'];                 // プレーンUTF-8で返す
                const body = Buffer.from(html, 'utf8');
                out['content-length'] = String(body.byteLength);
                delete out['transfer-encoding'];

                // ★ 常に強制モードを付与
                out['content-security-policy'] = enforceHeader;
                // ★ 監視を追加したい場合のみ併記
                if (reportOnlyHeader) {
                    out['content-security-policy-report-only'] = reportOnlyHeader;
                }

                res.writeHead(proxyRes.statusCode || 200, out);
                res.end(body);
            } catch (e) {
                console.error('[HTTP] CSP generation error:', e);
                const out = sanitizeResHeaders(proxyRes.headers || {});
                res.writeHead(proxyRes.statusCode || 502, out);
                res.end(Buffer.concat(chunks));
            }
        });

        proxyRes.on('error', err => {
            console.error('[HTTP] Upstream response error:', err);
            res.writeHead(502); res.end('Bad Gateway');
        });
    });

    proxyReq.on('error', err => {
        console.error('[HTTP] Error forwarding request:', err);
        res.writeHead(502); res.end('Bad Gateway');
    });

    req.pipe(proxyReq);
}).listen(8080, '0.0.0.0', () => {
    console.log('Internal HTTP server listening on 8080 (CSP always; Report-Only optional)');
});

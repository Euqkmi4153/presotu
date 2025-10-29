// internal_http_server.js (ESM)
import http from 'http';
import https from 'https';
import zlib from 'zlib';
import { promisify } from 'util';
import { generateCSP } from './csp-generator.mjs';

const gunzip = promisify(zlib.gunzip);
const brotliDecompress = zlib.brotliDecompress ? promisify(zlib.brotliDecompress) : null;

// ===== 運用スイッチ =====
const ADD_REPORT_ONLY = true;       // 監視ヘッダも同時に送る
const MODE = 'compat';              // 互換重視。厳格化は 'nonce'
const REPORT_ONLY_STYLE = 'monitor';// ← Trusted Types を含む監視重視型

/* ---------- ユーティリティ ---------- */
function normalizeHostParts(url) {
    return {
        normalizedHostname: url.hostname.replace(/\.$/, ''),
        normalizedHost: url.host.replace(/\.$/, ''),
    };
}

/* hop-by-hop 等の除去（→ 上流へ） */
function sanitizeReqHeaders(h) {
    const out = { ...h };
    delete out['proxy-connection'];
    delete out['connection'];
    delete out['keep-alive'];
    delete out['te'];
    delete out['trailer'];
    delete out['upgrade'];
    delete out['expect'];
    // 値が undefined のキーは除去
    Object.keys(out).forEach(k => { if (typeof out[k] === 'undefined') delete out[k]; });
    return out;
}

/* hop-by-hop の除去 + TE/CL 競合対策（← クライアントへ） */
function sanitizeResHeaders(h) {
    const out = { ...h };
    delete out['proxy-connection'];
    delete out['connection'];
    delete out['keep-alive'];
    delete out['te'];
    delete out['trailer'];
    delete out['upgrade'];
    // TE がある場合は CL を必ず削除（RFC 的に両立不可）
    if (typeof out['transfer-encoding'] === 'string' && out['transfer-encoding'] !== '') {
        delete out['content-length'];
    }
    return out;
}

async function maybeDecodeBody(raw, encoding) {
    if (!encoding) return raw;
    const enc = String(encoding).toLowerCase();
    try {
        if (enc.includes('gzip')) return await gunzip(raw);
        if (enc.includes('br') && brotliDecompress) return await brotliDecompress(raw);
        return raw;
    } catch {
        return raw;
    }
}

/* ---------- サーバ本体 ---------- */
http.createServer((req, res) => {
    const rawUrl = req.url.startsWith('http') ? req.url : `https://${req.headers.host}${req.url}`;
    const targetUrl = new URL(rawUrl);
    const { normalizedHostname, normalizedHost } = normalizeHostParts(targetUrl);

    // フォワード用ヘッダ
    const fwdHeaders = sanitizeReqHeaders(req.headers || {});
    fwdHeaders.host = normalizedHost;
    fwdHeaders.connection = 'close';
    // 上流からの圧縮を抑える（HTML を処理しやすくする）
    if (!fwdHeaders['accept-encoding']) fwdHeaders['accept-encoding'] = 'identity';

    const method = (req.method || 'GET').toUpperCase();
    // ★ ここで transfer-encoding: chunked は付けない（Node に任せる）
    // （自前で付けると TE/CL 競合を引き起こしやすい）

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
            // 非HTMLは基本そのままストリーム返却
            const out = sanitizeResHeaders(proxyRes.headers || {});
            // ここではボディをいじらないため、content-encoding/transfer-encoding はそのまま
            // ただし sanitizeResHeaders で TE がある場合は CL を落としている
            res.writeHead(proxyRes.statusCode || 200, out);
            proxyRes.pipe(res);
            return;
        }

        // HTML はバッファリングして CSP を付与
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', async () => {
            try {
                const raw = Buffer.concat(chunks);
                const decoded = await maybeDecodeBody(raw, proxyRes.headers['content-encoding']);
                const html = decoded.toString('utf8');

                const { enforceHeader, reportOnlyHeader } = await generateCSP(
                    targetUrl.href,
                    html,
                    {
                        mode: MODE,
                        addReportOnly: ADD_REPORT_ONLY,
                        reportOnlyStyle: REPORT_ONLY_STYLE,   // ← 監視重視（TT含む）
                        reportUri: '/csp-report',
                    }
                );

                const out = sanitizeResHeaders(proxyRes.headers || {});
                // 平文で返すためエンコード系と TE は必ず削除
                delete out['content-encoding'];
                delete out['transfer-encoding'];

                // 正確な Content-Length を付与
                const body = Buffer.from(html, 'utf8');
                out['content-length'] = String(body.byteLength);

                // 強制CSPは常時付与
                out['content-security-policy'] = enforceHeader;
                // 監視（Report-Only）はオプションで付与
                if (reportOnlyHeader) {
                    out['content-security-policy-report-only'] = reportOnlyHeader;
                }

                res.writeHead(proxyRes.statusCode || 200, out);
                res.end(body);
            } catch (e) {
                console.error('[HTTP] CSP generation error:', e);
                const out = sanitizeResHeaders(proxyRes.headers || {});
                // エラー時は素のレスポンスに戻す（decode 済みの raw をそのまま返すのは避ける）
                res.writeHead(proxyRes.statusCode || 502, out);
                res.end(Buffer.concat(chunks));
            }
        });

        proxyRes.on('error', err => {
            console.error('[HTTP] Upstream response error:', err);
            res.writeHead(502);
            res.end('Bad Gateway');
        });
    });

    proxyReq.on('error', err => {
        console.error('[HTTP] Error forwarding request:', err);
        res.writeHead(502);
        res.end('Bad Gateway');
    });

    // リクエストボディはストリーム転送（TE/CL は Node に任せる）
    req.pipe(proxyReq);
}).listen(8080, '0.0.0.0', () => {
    console.log('Internal HTTP server listening on 8080 (CSP always; Report-Only optional with TT monitor)');
});

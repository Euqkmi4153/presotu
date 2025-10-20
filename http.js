// file: internal_http_server.js  (ESM)
// package.json に "type": "module" を設定するか .mjs に変更してください
import http from 'http';
import https from 'https';
import zlib from 'zlib';
import { promisify } from 'util';
import { generateCSP } from './csp-generator.mjs';

const gunzip = promisify(zlib.gunzip);
const brotliDecompress = zlib.brotliDecompress ? promisify(zlib.brotliDecompress) : null;

function normalizeHostParts(url) {
    return {
        normalizedHostname: url.hostname.replace(/\.$/, ''),
        normalizedHost: url.host.replace(/\.$/, '')
    };
}

/* リクエスト側ヘッダのサニタイズ */
function dropHopByHopHeaders(headers) {
    const h = { ...headers };
    delete h['proxy-connection'];
    delete h['connection'];
    delete h['keep-alive'];
    delete h['te'];
    delete h['trailer'];
    delete h['upgrade'];
    delete h['expect'];
    delete h['transfer-encoding'];
    delete h['content-length'];
    return h;
}

/* レスポンス側ヘッダのサニタイズ（上流->クライアント） */
function sanitizeResponseHeaders(headers) {
    const h = { ...headers };
    // drop hop-by-hop
    delete h['proxy-connection'];
    delete h['connection'];
    delete h['keep-alive'];
    delete h['te'];
    delete h['trailer'];
    delete h['upgrade'];
    // 最も安全な取り扱い: upstream に transfer-encoding があっても content-length を外す、
    // さらに直接 transfer-encoding ヘッダも外して Node に任せて chunked を付けさせる方式にする
    delete h['content-length'];
    delete h['transfer-encoding'];
    return h;
}

async function maybeDecodeBody(raw, encoding) {
    if (!encoding) return raw;
    const enc = encoding.toLowerCase();
    try {
        if (enc.includes('gzip')) return await gunzip(raw);
        if (enc.includes('br') && brotliDecompress) return await brotliDecompress(raw);
        return raw;
    } catch {
        return raw;
    }
}

http.createServer((req, res) => {
    const rawUrl = req.url.startsWith('http') ? req.url : `https://${req.headers.host}${req.url}`;
    const targetUrl = new URL(rawUrl);
    const { normalizedHostname, normalizedHost } = normalizeHostParts(targetUrl);

    const fwdHeaders = dropHopByHopHeaders(req.headers || {});
    fwdHeaders.host = normalizedHost;
    fwdHeaders.connection = 'close';
    // accept-encoding を制限して upstream の変なヘッダ発生を抑える（オプション）
    fwdHeaders['accept-encoding'] = 'identity';

    const proxyOptions = {
        hostname: normalizedHostname,
        port: 443,
        path: targetUrl.pathname + targetUrl.search,
        method: req.method,
        headers: fwdHeaders,
        servername: normalizedHostname,
        ALPNProtocols: ['http/1.1'],
        insecureHTTPParser: true,
    };

    const proxyReq = https.request(proxyOptions, (proxyRes) => {
        // デバッグログ: upstream の生ヘッダを出す（原因特定に必須）
        console.log('[DEBUG upstream headers]', normalizedHostname, proxyRes.statusCode, proxyRes.headers);

        const contentType = (proxyRes.headers['content-type'] || '').toLowerCase();
        const isHtml = contentType.includes('text/html');

        if (!isHtml) {
            // 非HTMLはヘッダをサニタイズしてから返す（transfer/content-length 削除済み）
            const outHeaders = sanitizeResponseHeaders(proxyRes.headers || {});
            res.writeHead(proxyRes.statusCode || 200, outHeaders);
            proxyRes.pipe(res);
            return;
        }

        // HTML はバッファリングして CSP を生成して返す
        const chunks = [];
        proxyRes.on('data', (c) => chunks.push(c));
        proxyRes.on('end', async () => {
            try {
                const raw = Buffer.concat(chunks);
                const encoding = proxyRes.headers['content-encoding'];
                const decoded = await maybeDecodeBody(raw, encoding);
                const html = decoded.toString('utf8');

                const { header } = await generateCSP(targetUrl.href, html, { mode: 'compat' });

                const outHeaders = sanitizeResponseHeaders(proxyRes.headers || {});
                // rewrite: return plain UTF-8 with proper length (no transfer-encoding)
                outHeaders['content-security-policy'] = header;
                delete outHeaders['content-encoding'];
                delete outHeaders['content-length'];

                const outBody = Buffer.from(html, 'utf8');
                outHeaders['content-length'] = String(outBody.byteLength);

                res.writeHead(proxyRes.statusCode || 200, outHeaders);
                res.end(outBody);
            } catch (e) {
                console.error('[HTTP] CSP generation error:', e && e.stack ? e.stack : e);
                const outHeaders = sanitizeResponseHeaders(proxyRes.headers || {});
                res.writeHead(proxyRes.statusCode || 502, outHeaders);
                res.end(Buffer.concat(chunks));
            }
        });

        proxyRes.on('error', (err) => {
            console.error('[HTTP] Upstream response error:', err);
            res.writeHead(502);
            res.end('Bad Gateway');
        });
    });

    proxyReq.on('error', (err) => {
        console.error('[HTTP] Error forwarding request:', err);
        res.writeHead(502);
        res.end('Bad Gateway');
    });

    // リクエストボディをそのまま上流にストリーム
    req.pipe(proxyReq);
}).listen(8080, '0.0.0.0', () => {
    console.log('Internal HTTP server with CSP listening on port 8080');
});

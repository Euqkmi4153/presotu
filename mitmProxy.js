/* mitmproxy.js  — CommonJS */
const mitm = require('http-mitm-proxy');
const fs = require('fs');
const path = require('path');

const Mitm = typeof mitm === 'function' ? mitm : mitm.Proxy;
const proxy = new Mitm();

/* 起動時にホスト証明書キャッシュをクリーン */
(function cleanCache() {
    const base = '.http-mitm-proxy';
    ['certs', 'keys'].forEach(d => {
        const dir = path.join(base, d);
        if (!fs.existsSync(dir)) return;
        for (const f of fs.readdirSync(dir))
            if (!f.startsWith('ca.') && !f.startsWith('subCA.')) fs.unlinkSync(path.join(dir, f));
    });
    console.log('[INIT] old host-cert cache cleared');
})();

proxy.onError((ctx, err) => {
    if (err && err.code === 'EPIPE') return;
    console.error('[MITM] Proxy error:', err && err.stack ? err.stack : err);
});

/* リクエストヘッダ: hop-by-hop のみ削除（CL/TE は残す） */
function sanitizeReqHeaders(h) {
    const out = { ...h };
    delete out['proxy-connection'];
    delete out['connection'];
    delete out['keep-alive'];
    delete out['te'];
    delete out['trailer'];
    delete out['upgrade'];
    delete out['expect'];
    // CL/TE は残す
    Object.keys(out).forEach(k => { if (typeof out[k] === 'undefined') delete out[k]; });
    return out;
}

/* リクエスト → 内部 HTTP サーバーへ横流し */
proxy.onRequest((ctx, cb) => {
    const req = ctx.clientToProxyRequest;
    const rawUrl = req && req.url ? req.url : '/';
    const url = rawUrl.startsWith('http') ? new URL(rawUrl)
        : new URL(`https://${req.headers.host}${rawUrl}`);

    const safeHeaders = sanitizeReqHeaders(req.headers || {});
    // Host は正規化（末尾ドット除去）
    safeHeaders.host = (url.host || '').replace(/\.$/, '');

    // CL がなく、ボディを持つ可能性があり、TE も無いときは chunked を明示
    const method = (req.method || 'GET').toUpperCase();
    const mayHaveBody = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
    const hasCL = typeof req.headers['content-length'] === 'string' && req.headers['content-length'] !== '';
    const hasTE = typeof req.headers['transfer-encoding'] === 'string' && req.headers['transfer-encoding'] !== '';
    if (mayHaveBody && !hasCL && !hasTE) {
        safeHeaders['transfer-encoding'] = 'chunked';
    }

    ctx.proxyToServerRequestOptions = {
        protocol: 'http:',
        hostname: 'localhost',
        port: 8080,
        path: url.pathname + url.search,
        method,
        headers: safeHeaders,
    };
    ctx.isSSL = false;
    ctx.connectToServer = false;
    cb();
});

/* レスポンスは素通し（CSP は内部HTTPサーバ側で付与） */
proxy.onResponse((ctx, cb) => cb());

proxy.listen({
    host: '0.0.0.0',
    port: 3000,
    sslCaDir: './.http-mitm-proxy',
    caCertPath: './.http-mitm-proxy/certs/subCA.cer',
    caPrivateKeyPath: './.http-mitm-proxy/keys/subCA.key',
    caCertChainPath: './.http-mitm-proxy/certs/fullchain.pem'
}, () => {
    console.log('MITM proxy listening on 3000');
});

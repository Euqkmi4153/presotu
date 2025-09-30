/* mitmproxy.js
   run:  node mitmproxy.js
----------------------------------------------------*/
const mitm = require('http-mitm-proxy');   // v1./v2 どちらも可
const zlib = require('zlib');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');
const gunzip = promisify(zlib.gunzip);
const gzip = promisify(zlib.gzip);

/* ── ESM モジュールを動的 import ── */
let genCSP;
(async () => { genCSP = (await import('./csp-generator-practice.mjs')).generateCSP; })();

/* ── プロキシ実体 ── */
const Mitm = typeof mitm === 'function' ? mitm : mitm.Proxy;
const proxy = new Mitm();

/* :::: 起動時にホスト証明書キャッシュをクリーン ::: */
(function cleanCache() {
    const base = '.http-mitm-proxy';
    ['certs', 'keys'].forEach(d => {
        const dir = path.join(base, d);
        if (!fs.existsSync(dir)) return;
        for (const f of fs.readdirSync(dir))
            if (!f.startsWith('ca.') && !f.startsWith('subCA.')) fs.unlinkSync(path.join(dir, f));
    });
    console.log('[INIT] old host‑cert cache cleared');
})();

/* ::::: イベント ::::: */
proxy.onError((ctx, err) => {
    if (err.code === 'EPIPE') return;
    console.error('Proxy error:', err);
});

/* リクエスト → 内部 HTTPS サーバーへ横流し */
proxy.onRequest((ctx, cb) => {
    const req = ctx.clientToProxyRequest;
    const url = req.url.startsWith('http') ? new URL(req.url)
        : new URL(`https://${req.headers.host}${req.url}`);
    ctx.proxyToServerRequestOptions = {
        protocol: 'http:',
        hostname: 'localhost',
        port: 8080,
        path: url.pathname + url.search,
        method: req.method,
        headers: { ...req.headers, host: url.hostname },
    };
    ctx.isSSL = false;
    ctx.connectToServer = false;
    cb();
});

/* レスポンスフック：HTML だけ横取りして CSP を注入 */
proxy.onResponse((ctx, cb) => {
    const headers = ctx.serverToProxyResponse.headers;
    const ct = (headers['content-type'] || '').toLowerCase();
    if (!ct.includes('text/html')) {
        return cb();   // HTML 以外は素通し
    }

    if (typeof mitm.gunzip === 'function') {
        ctx.use(mitm.gunzip());        // ✅ () を付けてミドルウェア・オブジェクトを渡す
    }
    const bufs = [];
    ctx.onResponseData((_, chunk, done) => {
        if (chunk) bufs.push(chunk);                 // バッファリング
        done(null, null);                            // クライアントへは流さない
    });
    ctx.onResponseEnd(async (_, done) => {
        try {
            const raw = Buffer.concat(bufs);
            const decoded = (headers['content-encoding'] || '').includes('gzip')
                ? await gunzip(raw).catch(() => raw)
                : raw;
            const html = decoded.toString();

            // --- 生成した CSP ---
            const req = ctx.clientToProxyRequest;
            const fullURL = req.url.startsWith('http')
                ? req.url
                : `https://${req.headers.host}${req.url}`;
            const csp = await genCSP(fullURL, html);

            // --- ヘッダー調整 ---
            delete headers['content-length'];
            delete headers['content-encoding'];      // 平文で返す
            headers['content-security-policy'] = csp;

            // --- クライアントへ送出 ---
            ctx.proxyToClientResponse.write(html);
            ctx.proxyToClientResponse.end();
        } catch (e) {
            console.error('CSP inject error', e);
        }
        done();
    });
    cb();
});

/* ::::: 監視開始 ::::: */
proxy.listen({
    host: '0.0.0.0',
    port: 3000,
    sslCaDir: './.http-mitm-proxy',
    caCertPath: './.http-mitm-proxy/certs/subCA.cer',
    caPrivateKeyPath: './.http-mitm-proxy/keys/subCA.key',
    caCertChainPath: './.http-mitm-proxy/certs/fullchain.pem'
}, () => {
    console.log('MITM proxy listening on 3000')
});

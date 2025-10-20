/* mitmproxy.js
   run:  node mitmproxy.js
----------------------------------------------------*/
const mitm = require('http-mitm-proxy');   // v1./v2 どちらも可
const fs = require('fs');
const path = require('path');

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
    console.log('[INIT] old host-cert cache cleared');
})();

/* ::::: イベント ::::: */
proxy.onError((ctx, err) => {
    if (err && err.code === 'EPIPE') return;
    console.error('[MITM] Proxy error:', err && err.stack ? err.stack : err);

    try {
        if (ctx && ctx.serverToProxyResponse) {
            console.error('[MITM] upstream headers at error:', ctx.serverToProxyResponse.headers);
        }
        if (ctx && ctx.clientToProxyRequest) {
            console.error('[MITM] client request headers at error:', ctx.clientToProxyRequest.headers);
        }
    } catch (e) { /* ignore logging failure */ }
});

/* --- ヘッダサニタイズ（リクエストを内部サーバへ渡す前）--- */
function sanitizeReqHeaders(h) {
    const out = { ...h };
    // hop-by-hop / proxy 関連は削除
    delete out['proxy-connection'];
    delete out['connection'];
    delete out['keep-alive'];
    delete out['te'];
    delete out['trailer'];
    delete out['upgrade'];
    // 衝突の元を排除
    delete out['transfer-encoding'];
    delete out['content-length'];
    delete out['expect'];
    // undefined 値のキーは削除
    Object.keys(out).forEach(k => { if (typeof out[k] === 'undefined') delete out[k]; });
    return out;
}

/* リクエスト → 内部 HTTP サーバーへ横流し（ヘッダをサニタイズ） */
proxy.onRequest((ctx, cb) => {
    const req = ctx.clientToProxyRequest;
    const rawUrl = req && req.url ? req.url : '/';
    const url = rawUrl.startsWith('http') ? new URL(rawUrl)
        : new URL(`https://${req.headers.host}${rawUrl}`);

    const safeHeaders = sanitizeReqHeaders(req.headers || {});
    // 正規化された Host（末尾ドットを除去）
    safeHeaders.host = (url.host || '').replace(/\.$/, '');

    ctx.proxyToServerRequestOptions = {
        protocol: 'http:',
        hostname: 'localhost',  // 内部 HTTP サーバへ転送
        port: 8080,
        path: url.pathname + url.search,
        method: req.method,
        headers: safeHeaders,
    };
    ctx.isSSL = false;
    ctx.connectToServer = false;

    // デバッグ: クライアントヘッダをログして問題追跡（必要時有効化）
    // console.log('[MITM] safeHeaders -> internal:', safeHeaders);

    cb();
});

/* レスポンスは素通し（CSP は HTTP サーバ側で付与） */
proxy.onResponse((ctx, cb) => cb());

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

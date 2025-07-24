const mitm = require('http-mitm-proxy');
const proxy = new mitm.Proxy();

proxy.onError((ctx, err) => {
    console.error('Proxy error:', err);
});

proxy.onRequest((ctx, callback) => {
    try {
        const req = ctx.clientToProxyRequest;
        const url = req.url.startsWith('http')
            ? new URL(req.url)
            : new URL(`https://${req.headers.host}${req.url}`);

        ctx.proxyToServerRequestOptions.hostname = 'localhost';
        ctx.proxyToServerRequestOptions.port = 8080;
        ctx.proxyToServerRequestOptions.path = url.pathname + url.search;
        ctx.proxyToServerRequestOptions.headers.host = url.hostname;

        // --- ここを追加 ---
        // 内部サーバーが自己署名証明書を使用している場合、検証を無効にする
        ctx.proxyToServerRequestOptions.rejectUnauthorized = false;
        // --- ここまで追加 ---

        console.log(`[MITM] Forwarding to internal server: ${url.href}`);
    } catch (err) {
        console.error('URL parsing error:', err);
    }
    return callback();
});

proxy.onResponse((ctx, callback) => {
    const cspHeader =
        "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none';";
    ctx.serverToProxyResponse.headers['content-security-policy'] = cspHeader;
    return callback();
});

proxy.listen(
    {
        port: 3000,
        sslCaDir: './.http-mitm-proxy',
    },
    () => {
        console.log('MITM proxy listening on port 3000');
    }
);
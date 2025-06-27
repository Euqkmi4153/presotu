const mitm = require('http-mitm-proxy');
const proxy = new mitm.Proxy();

proxy.onError((ctx, err) => {
    console.error('Proxy error:', err);
});

proxy.onRequest((ctx, callback) => {
    try {
        const req = ctx.clientToProxyRequest;
        const url = req.url.startsWith("http") ? new URL(req.url) : new URL(`https://${req.headers.host}${req.url}`);

        ctx.proxyToServerRequestOptions.hostname = "localhost";
        ctx.proxyToServerRequestOptions.port = 8080;
        ctx.proxyToServerRequestOptions.path = url.pathname + url.search;
        ctx.proxyToServerRequestOptions.headers.host = url.hostname;

        ctx.proxyToServerRequestOptions.rejectUnauthorized = false;

        console.log(`[MITM] Forwarding to internal server: ${url.href}`);
    } catch (err) {
        console.error("URL parsing error:", err);
    }
    return callback();
});

proxy.onResponse((ctx, callback) => {
    const cspHeader = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none';";
    ctx.serverToProxyResponse.headers['content-security-policy'] = cspHeader;
    return callback();
});

proxy.listen({
    host: '0.0.0.0',
    port: 3000,
    sslCaDir: './.http-mitm-proxy',
    caCertPath: './.http-mitm-proxy/certs/ca.cer',
    caPrivateKeyPath: './.http-mitm-proxy/keys/ca.private.key'
}, () => {
    console.log('MITM proxy listening on port 3000');
});

const mitm = require('http-mitm-proxy');
const proxy = new mitm.Proxy();

proxy.onError((ctx, err) => {
    console.error('Proxy error:', err);
});

proxy.onRequest((ctx, callback) => {
    try {
        const req = ctx.clientToProxyRequest;
        const url = req.url.startsWith("http") ? new URL(req.url) : new URL(`https://${req.headers.host}${req.url}`);

        ctx.proxyToServerRequestOptions = {
            protocol: 'http:',
            hostname: 'localhost',
            port: 8080,
            path: url.pathname + url.search,
            method: req.method,
            headers: { ...req.headers, host: url.hostname }
        };
        // ctx.proxyToServerRequestOptions.rejectUnauthorized = false;
        ctx.isSSL = false;
        ctx.connectToServer = false;

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
    caCertPath: './.http-mitm-proxy/certs/subCA.cer',
    caPrivateKeyPath: './.http-mitm-proxy/keys/subCA.key',
    caCertChainPath: './.http-mitm-proxy/certs/fullchain.pem'

}, () => {
    console.log('MITM proxy listening on port 3000');
});

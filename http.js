// internal_http_server.js
const http = require("http");
const https = require("https");
const fs = require("fs");

const options = {
    key: fs.readFileSync('./.http-mitm-proxy/keys/ca.private.key'),
    cert: fs.readFileSync('./.http-mitm-proxy/certs/ca.cer'),
};

https.createServer(options, (req, res) => {
    const targetUrl = new URL(req.url.startsWith("http") ? req.url : `https://${req.headers.host}${req.url}`);

    const proxyOptions = {
        hostname: targetUrl.hostname,
        port: 443,
        path: targetUrl.pathname + targetUrl.search,
        method: req.method,
        headers: {
            ...req.headers,
            host: targetUrl.hostname
        },
        servername: targetUrl.hostname
    };

    const proxyReq = https.request(proxyOptions, (proxyRes) => {
        // CSPヘッダを追加
        const headers = {
            ...proxyRes.headers,
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none';"
        };

        res.writeHead(proxyRes.statusCode, headers);
        proxyRes.pipe(res);
    });

    req.pipe(proxyReq);

    proxyReq.on("error", err => {
        console.error("Error forwarding request:", err);
        res.writeHead(502);
        res.end("Bad Gateway");
    });
}).listen(8080, () => {
    console.log("Internal HTTP server listening on port 8080");
});

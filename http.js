const http = require("http");
const https = require("https");

http.createServer((req, res) => {
    const options = {
        hostname: "httpbin.org",
        port: 443,
        path: req.url,
        method: req.method,
        headers: {
            ...req.headers,
            host: "httpbin.org"
        },
        servername: "httpbin.org" // TLS証明書照合用
    };

    const extReq = https.request(options, extRes => {
        const headers = {
            ...extRes.headers,
            "Content-Security-Policy": "default-src 'self'"
        };

        res.writeHead(extRes.statusCode, headers);
        extRes.pipe(res);
    });

    req.pipe(extReq);

    extReq.on("error", err => {
        console.error("Error contacting external server:", err);
        res.writeHead(502);
        res.end("Bad Gateway");
    });
}).listen(3000, () => {
    console.log("Internal HTTP handler listening on port 3000");
});

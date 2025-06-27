// const express = require("express")
// const https = require("https")
// const http = require("http")
// const path = require("path")
// const fs = require("fs")
// const httpProxy = require('http-proxy');
// const app = express()
// const tlsApp = express();
// app.get("/", (req, res) => {
//     res.send("Hello geeks, I am running on http!")
// })
// tlsApp.get("/", (req, res) => {
//     res.send("Hello geeks, I am running on https!")
// })

// const options = {
//     key: fs.readFileSync('key.pem'),
//     cert: fs.readFileSync('cert.pem')
// };

// const proxy = httpProxy.createProxyServer({});


// const httpServer = http.createServer(app)
// const httpsServer = https.createServer({
//     key: fs.readFileSync(path.join(__dirname,
//         "certificates", "key.pem")),
//     cert: fs.readFileSync(path.join(__dirname,
//         "certificates", "cert.pem")),
// },
//     tlsApp
// )

// httpServer.listen(3000, () => {
//     console.log("HTTP server up and running on port 3000")
// })
// httpsServer.listen(3001, () => {
//     console.log("HTTPS server up and running on port 3001")

// })
// https.createServer(options, (req, res) => {
//     const target = req.url.startsWith('http') ? req.url : 'http://localhost:3000'; // 必要に応じてターゲットを設定
//     proxy.web(req, res, { target: target }, (e) => {
//         console.error('Proxy error:', e);
//         res.writeHead(502);
//         res.end('Bad gateway');
//     });
// }).listen(443, () => {
//     console.log('HTTPS Proxy server is running on port 443');
// });

const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");

const options = {
    key: fs.readFileSync(path.join(__dirname, "certificates", "key.pem")),
    cert: fs.readFileSync(path.join(__dirname, "certificates", "cert.pem"))
};

// HTTPS で受け取り、HTTPサーバーに転送
https.createServer(options, (req, res) => {
    const proxyReq = http.request(
        {
            hostname: "localhost",
            port: 3000,
            path: req.url,
            method: req.method,
            headers: req.headers
        },
        proxyRes => {
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res);
        }
    );

    req.pipe(proxyReq);
    proxyReq.on("error", err => {
        console.error("Error forwarding to HTTP server:", err);
        res.writeHead(502);
        res.end("Bad Gateway");
    });
}).listen(443, () => {
    console.log("HTTPS proxy listening on port 443");
});

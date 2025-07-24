// ---------------------------------------------------------------------------
// mitmproxy_fullchain.js
// ---------------------------------------------------------------------------
// このファイルでは、http‑mitm‑proxy を使った MITM プロキシに「フルチェーン
// （Leaf + 中間 SubCA）」を必ず送信させる実装を追加しています。
// ポイントは次の 2 点です。
//   1. プロキシ起動時に subCA.cer を読み込み、fullchain.pem を動的生成。
//      → http‑mitm‑proxy の `caCertChainPath` に渡す。
//   2. それ以外のロジック（リクエスト転送・CSP 付与）は従来どおり。
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const mitm = require('http-mitm-proxy');
const proxy = new mitm.Proxy();

//------------------------------------------------------------------
// 1)  フルチェーン PEM を準備（Leaf 証明書の後ろに付くチェーン部分）
//------------------------------------------------------------------
// ディレクトリ定義
const CERT_DIR = path.resolve(__dirname, '.http-mitm-proxy', 'certs');
const KEY_DIR = path.resolve(__dirname, '.http-mitm-proxy', 'keys');

const subCAPath = path.join(CERT_DIR, 'subCA.cer');  // 中間 CA
const fullChainPath = path.join(CERT_DIR, 'fullchain.pem'); // ← ここを proxy に渡す

// subCA.cer を読み込み、余計な空行を削って書き出す（毎回上書きで安全）
const subCAPem = fs.readFileSync(subCAPath, 'utf8').trimEnd() + '\n';
fs.writeFileSync(fullChainPath, subCAPem, 'utf8');

//------------------------------------------------------------------
// 2)  エラー処理
//------------------------------------------------------------------
proxy.onError((ctx, err) => {
    console.error('Proxy error:', err);
});

//------------------------------------------------------------------
// 3)  リクエストを内部 HTTP サーバーへフォワード
//------------------------------------------------------------------
proxy.onRequest((ctx, callback) => {
    try {
        const req = ctx.clientToProxyRequest;
        const url = req.url.startsWith('http')
            ? new URL(req.url)
            : new URL(`https://${req.headers.host}${req.url}`);

        ctx.proxyToServerRequestOptions = {
            protocol: 'http:',
            hostname: 'localhost',
            port: 8080,
            path: url.pathname + url.search,
            method: req.method,
            headers: { ...req.headers, host: url.hostname }
        };

        ctx.isSSL = false;          // 内部 HTTP サーバーはプレーン HTTP
        ctx.connectToServer = false;

        console.log(`[MITM] Forwarding to internal server: ${url.href}`);
    } catch (err) {
        console.error('URL parsing error:', err);
    }
    return callback();
});

//------------------------------------------------------------------
// 4)  レスポンスヘッダに CSP 付与
//------------------------------------------------------------------
proxy.onResponse((ctx, callback) => {
    const cspHeader = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none';";
    ctx.serverToProxyResponse.headers['content-security-policy'] = cspHeader;
    return callback();
});

//------------------------------------------------------------------
// 5)  プロキシ起動。caCertChainPath に fullchain.pem を渡すのがキモ
//------------------------------------------------------------------
proxy.listen({
    host: '0.0.0.0',
    port: 3000,
    sslCaDir: './.http-mitm-proxy',
    caCertPath: subCAPath,                // 中間 CA が署名者
    caPrivateKeyPath: path.join(KEY_DIR, 'subCA.key'),
    caCertChainPath: fullChainPath        // ← ここを必ず指定！
}, () => {
    console.log('MITM proxy listening on port 3000 (full chain mode)');
});

//------------------------------------------------------------------
// 6)  internal_http_server.js も同ディレクトリに置く想定（変更なし）
//------------------------------------------------------------------
//  ※既存の internal_http_server.js に変更はありませんが、参考として
//    すぐ下に同梱しておきます。
//------------------------------------------------------------------

/* -------------------------------------------------------------------------
// internal_http_server.js
// -------------------------------------------------------------------------
// 内部 HTTP サーバーはクライアントから平文 HTTP を受け取り、ターゲットの
// HTTPS サイトへ再発行してレスポンスに CSP を付与するだけのシンプルな
// リバースプロキシです。こちらは以前のコードから変更ありません。
----------------------------------------------------------------------------*/
/*
const http  = require('http');
const https = require('https');

http.createServer((req, res) => {
  const targetUrl = new URL(req.url.startsWith('http') ? req.url : `https://${req.headers.host}${req.url}`);

  const proxyOptions = {
    hostname: targetUrl.hostname,
    port: 443,
    path: targetUrl.pathname + targetUrl.search,
    method: req.method,
    headers: { ...req.headers, host: targetUrl.hostname },
    servername: targetUrl.hostname
  };

  const proxyReq = https.request(proxyOptions, (proxyRes) => {
    const headers = {
      ...proxyRes.headers,
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none';"
    };
    res.writeHead(proxyRes.statusCode, headers);
    proxyRes.pipe(res);
  });

  req.pipe(proxyReq);

  proxyReq.on('error', err => {
    console.error('Error forwarding request:', err);
    res.writeHead(502);
    res.end('Bad Gateway');
  });
}).listen(8080, () => {
  console.log('Internal HTTP server listening on port 8080');
});
*/

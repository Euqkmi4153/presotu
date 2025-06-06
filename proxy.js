// const express = require("express");
// const request = require("request");
// const app = express();

// app.get('/', (req, res) => {
//     console.log('GETリクエストを受け取りました');

//     res.setHeader('Content-Security-Policy',
//         "default-src 'self'; " +
//         "script-src ; " +
//         "style-src 'self'; " +
//         "object-src 'none'; " +
//         "img-src 'none' ;" +
//         "base-uri 'self'; " +
//         "form-action 'self';"
//     );
//     console.log(res);
// });
// app.use((req, res) => {
//     const targetUrl = req.url;
//     if (!targetUrl) {
//         res.status(400).send("Error: Please provide a URL as a query parameter.");
//         return;
//     }
//     // targetUrl にリクエストを送信し、レスポンスをクライアントにパイプ
//     request(targetUrl)
//         .on("response", (response) => {
//             // レスポンスのヘッダーをそのまま転送
//             res.status(response.statusCode);
//         })
//         .on("error", (error) => {
//             console.error(`Error fetching ${targetUrl}:`, error);
//             res.status(500).send(`Error occurred while fetching the target URL: ${error.message}`);
//         })

//         .pipe(res);
// });
// const PORT = 3000;
// app.listen(PORT, () => {
//     console.log(`Proxy server is running on http://10.1.248.161:${PORT}`);
// });

// const express = require("express");
// const request = require("request");
// const app = express();

// // プロキシサーバー
// app.use((req, res) => {
//     const targetUrl = req.url; // クエリパラメータからターゲットURLを取得
//     console.log(targetUrl)
//     if (!targetUrl) {
//         res.status(400).send("Error: Please provide a URL as a query parameter, e.g., ?url=http://example.com");
//         return;
//     }

//     // リクエスト送信
//     request(targetUrl, (error, response, body) => {
//         if (error) {
//             console.error(`Error fetching ${targetUrl}:`, error);
//             res.status(500).send(`Error occurred while fetching the target URL: ${error.message}`);
//             return;
//         }

//         // コンテンツタイプを確認（HTMLかどうか）
//         const contentType = response.headers["content-type"] || "";
//         if (contentType.includes("text/html")) {
//             // HTMLの場合、<meta>タグを挿入してCSPを適用
//             const modifiedBody = body.replace(
//                 /<head>/i, // <head>タグの直後に<meta>タグを挿入
//                 `<head>
//                 <meta http-equiv="Content-Security-Policy" content="
//                     default-src 'self';
//                     script-src 'self';
//                     style-src 'self';
//                     object-src 'none';
//                     img-src 'none';
//                     base-uri 'self';
//                     form-action 'self';
//                 ">
//                 `
//             );
//             res.set("Content-Type", contentType); // コンテンツタイプをそのまま設定
//             res.send(modifiedBody); // 修正済みHTMLを送信
//         } else {
//             // HTML以外のコンテンツはそのまま転送
//             res.set(response.headers); // 元のレスポンスヘッダーを転送
//             res.status(response.statusCode).send(body);
//         }
//     });
// });

// // サーバー起動
// const PORT = 3000;
// app.listen(PORT, () => {
//     console.log(`Proxy server is running on http://10.1.248.161:${PORT}`);
// });

// const express = require("express");
// const request = require("request");
// const app = express();

// // 共通のCSPポリシー（デフォルト値）
// const CSP_POLICY = `
//     default-src 'self';
//     script-src 'self';
//     style-src 'self';
//     object-src 'none';
//     img-src 'none';
//     base-uri 'self';
//     form-action 'self';
// `;

// // HTMLレスポンスに<meta>タグを挿入してCSPを適用
// function injectCSP(html, targetUrl) {
//     let cspPolicy = CSP_POLICY;

//     // ターゲットURLに応じてCSPを変更
//     if (targetUrl.includes("top.html")) {
//         cspPolicy = `
//             default-src 'self';
//             script-src 'self' 'unsafe-inline';
//             img-src 'self';
//         `;
//     } else if (targetUrl.includes("menu.html")) {
//         cspPolicy = `
//             default-src 'self';
//             script-src 'none';
//             img-src 'none';
//         `;
//     }

//     return html.replace(
//         /<head>/i,
//         `<head>
//         <meta http-equiv="Content-Security-Policy" content="${cspPolicy}">
//         `
//     );
// }

// // プロキシサーバー
// app.use((req, res) => {
//     const targetUrl = req.query.url; // クエリパラメータでターゲットURLを取得
//     if (!targetUrl) {
//         res.status(400).send("Error: Please provide a URL as a query parameter, e.g., ?url=http://example.com");
//         return;
//     }

//     // ターゲットURLへのリクエストを送信
//     request(targetUrl, (error, response, body) => {
//         if (error) {
//             console.error(`Error fetching ${targetUrl}:`, error);
//             res.status(500).send(`Error occurred while fetching the target URL: ${error.message}`);
//             return;
//         }

//         // コンテンツタイプを確認
//         const contentType = response.headers["content-type"] || "";
//         if (contentType.includes("text/html")) {
//             // HTMLコンテンツの場合、ターゲットURLに応じてCSPを挿入
//             const modifiedBody = injectCSP(body, targetUrl);
//             res.set("Content-Type", contentType); // コンテンツタイプをそのまま設定
//             res.send(modifiedBody); // 修正済みHTMLを送信
//         } else {
//             // HTML以外のコンテンツはそのまま転送
//             res.set(response.headers); // 元のレスポンスヘッダーを転送
//             res.status(response.statusCode).send(body);
//         }
//     });
// });

// // サーバー起動
// const PORT = 3000;
// app.listen(PORT, () => {
//     console.log(`Proxy server is running on http://10.1.248.161:${PORT}`);
// });

const express = require("express");
const request = require("request");
const app = express();

// 共通のCSPポリシー（デフォルト値）
const DEFAULT_CSP = `
    default-src 'self';
    script-src 'self';
    style-src 'self';
    object-src 'none';
    img-src 'none';
    base-uri 'self';
    form-action 'self';
`;

// ターゲットURLに応じてCSPを変更
function getCSPForTarget(url) {
    if (url.includes("menu.html")) {
        return `
            default-src 'self';
            script-src 'none';
            img-src 'none';
        `;
    } else if (url.includes("top.html")) {
        return `
            default-src 'self';
            script-src 'self' 'unsafe-inline';
            img-src 'self';
        `;
    }
    return DEFAULT_CSP; // 親ページやその他の場合のデフォルトCSP
}

// HTMLレスポンスに<meta>タグを挿入してCSPを適用
function injectCSP(html, cspPolicy) {
    return html.replace(
        /<head>/i,
        `<head>
        <meta http-equiv="Content-Security-Policy" content="${cspPolicy}">
        `
    );
}

// プロキシサーバー
app.use((req, res) => {
    const targetUrl = req.url; // クエリパラメータからターゲットURLを取得
    if (!targetUrl) {
        res.status(400).send("Error: Please provide a URL as a query parameter, e.g., ?url=http://example.com");
        return;
    }

    // ターゲットURLへのリクエストを送信
    request(targetUrl, (error, response, body) => {
        if (error) {
            console.error(`Error fetching ${targetUrl}:`, error);
            res.status(500).send(`Error occurred while fetching the target URL: ${error.message}`);
            return;
        }

        // コンテンツタイプを確認
        const contentType = response.headers["content-type"] || "";
        if (contentType.includes("text/html")) {
            let cspPolicy = getCSPForTarget(targetUrl);

            // フレームセットページの場合、内部のフレームURLをプロキシに向ける
            if (body.includes("<frameset")) {
                body = body.replace(/src="([^"]+)"/g, (match, src) => {
                    // フレームURLをプロキシ経由のURLに書き換え
                    const proxiedSrc = `/proxy?url=${encodeURIComponent(src)}`;
                    return `src="${proxiedSrc}"`;
                });
            }

            // HTMLにCSPを挿入
            const modifiedBody = injectCSP(body, cspPolicy);
            res.set("Content-Type", contentType);
            res.send(modifiedBody);
        } else {
            // HTML以外のコンテンツはそのまま転送
            res.set(response.headers);
            res.status(response.statusCode).send(body);
        }
    });
});

// サーバー起動
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Proxy server is running on http://10.1.248.161:${PORT}`);
});


const express = require("express");
const request = require("request");

const app = express();

app.use("/proxy", (req, res) => {
    const targetUrl = req.query.url;

    if (!targetUrl) {
        res.status(400).send("Error: Please provide a URL as a query parameter.");
        return;
    }

    // targetUrl にリクエストを送信し、レスポンスをクライアントにパイプ
    request(targetUrl)
        .on("response", (response) => {
            // レスポンスのヘッダーをそのまま転送
            res.status(response.statusCode);
        })
        .on("error", (error) => {
            console.error(`Error fetching ${targetUrl}:`, error);
            res.status(500).send(`Error occurred while fetching the target URL: ${error.message}`);
        })
        .pipe(res);
});

// サーバーを起動
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Proxy server is running on http://localhost:${PORT}`);
});


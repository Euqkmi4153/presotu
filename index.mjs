import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const PORT = 8080;

// __dirname を再現
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ルートリクエスト
app.get('/', (req, res) => {
    console.log('GETリクエストを受け取りました');

    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src; " +
        "style-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self';"
    );

    const filePath = path.join(__dirname, './index.html');
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(500).send('Error reading index.html');
        } else {
            res.setHeader('Content-Type', 'text/html');
            console.log(res);
            res.send(data);
        }
    });
});

// 静的ファイル (index.mjs) を処理
app.get('./index.mjs', (req, res) => {
    console.log('index.mjsリクエストを受け取りました');

    const filePath = path.join(__dirname, './index.mjs');
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(404).send('index.mjs not found');
        } else {
            res.setHeader('Content-Type', 'application/javascript'); // MIMEタイプを設定
            res.send(data);
        }
    });
});

// サーバーを起動
app.listen(PORT, () => {
    console.log(`サーバーを起動しました on http://10.1.248.161:${PORT}`);
});

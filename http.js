// internal_http_server.js (http.js) — CSP strict/nonce
import http from 'http';
import https from 'https';
import zlib from 'zlib';
import dns from 'dns';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomBytes } from 'crypto';
import { generateCSP } from './csp-generator.mjs';

const gunzip = promisify(zlib.gunzip);
const ADD_REPORT_ONLY = true;
const REPORT_URI = '/csp-report';

const LOCAL_ROOT = '/home/naoki/proxy-server/test/targetSite';
const LOCAL_FILES = { 1: 'targetSite1.html' };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ---------- HTML helpers ---------- */
function injectHelpers(html, nonce) {
    // base
    if (/<head[^>]*>/i.test(html) && !/<base\b[^>]*>/i.test(html)) {
        html = html.replace(/<head([^>]*)>/i, `<head$1><base href="/_localfs/">`);
    }
    // CSP violation logger (nonce付き)
    const helper = `
<script nonce="${nonce}">
window.addEventListener('securitypolicyviolation', e => {
  console.log('[CSP_VIOLATION]', {
    effectiveDirective: e.effectiveDirective,
    violatedDirective: e.violatedDirective,
    blockedURI: e.blockedURI
  });
});
</script>`;
    if (/<\/head>/i.test(html)) html = html.replace(/<\/head>/i, helper + '</head>');
    else html = helper + html;
    return html;
}

/* ---------- Local HTML + CSP ---------- */
async function serveLocalHTML(res, url, filePath) {
    try {
        const raw = fs.readFileSync(filePath, 'utf8');
        const nonce = randomBytes(16).toString('base64');
        const html = injectHelpers(raw, nonce);

        const { enforceHeader, reportOnlyHeader } =
            await generateCSP(url, html, {
                nonce,
                addReportOnly: ADD_REPORT_ONLY,
                reportUri: REPORT_URI
            });

        const headers = {
            'content-type': 'text/html; charset=utf-8',
            'content-security-policy': enforceHeader,
        };
        if (reportOnlyHeader) {
            headers['content-security-policy-report-only'] = reportOnlyHeader;
        }

        res.writeHead(200, headers);
        res.end(html);
    } catch (e) {
        console.error(e);
        res.writeHead(500);
        res.end('error');
    }
}

/* ---------- HTTP Server ---------- */
http.createServer((req, res) => {
    const raw = `http://${req.headers.host}${req.url}`;
    const u = new URL(raw);

    if (u.pathname === '/csp-report') {
        let body = [];
        req.on('data', c => body.push(c));
        req.on('end', () => {
            console.log('[CSP-REPORT]', Buffer.concat(body).toString());
            res.writeHead(204);
            res.end();
        });
        return;
    }

    if (u.pathname === '/_local_test1') {
        const file = path.join(LOCAL_ROOT, LOCAL_FILES[1]);
        serveLocalHTML(res, u.href, file);
        return;
    }

    res.writeHead(404);
    res.end('Not Found');
}).listen(8080, () => {
    console.log('[INIT] strict CSP (nonce) enabled');
});

/* csp-generator.mjs — “壊さず守る”互換モードを既定 */
import { JSDOM } from 'jsdom';
import axios from 'axios';
import * as csstree from 'css-tree';
import * as espree from 'espree';
import estraverse from 'estraverse';
import { createHash, randomBytes } from 'crypto';

/* ---------- utils ---------- */
const sha256 = s => createHash('sha256').update(s).digest('base64');
function addOrigin(set, raw, baseURL) {
    try {
        const u = new URL(raw, baseURL);
        if (u.protocol === 'http:' || u.protocol === 'https:') set.add(u.origin);
        else if (u.protocol === 'ws:' || u.protocol === 'wss:') set.add((u.protocol === 'wss:' ? 'https:' : 'http:') + '//' + u.host);
    } catch { }
}

/* ---------- base policies ---------- */
function basePolicyCompat() {
    return {
        "default-src": new Set(["'self'"]),
        "script-src": new Set(["'self'", "https:"]),
        "style-src": new Set(["'self'", "'unsafe-inline'", "https:"]),
        "img-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "font-src": new Set(["'self'", "data:", "https:"]),
        "connect-src": new Set(["'self'", "https:"]),
        "media-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "worker-src": new Set(["'self'", "blob:"]),
        "frame-src": new Set(["'self'"]),
        "form-action": new Set(["'self'"]),
    };
}
function basePolicyNonce(nonce) {
    return {
        "default-src": new Set(["'self'"]),
        "script-src": new Set(["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"]),
        "style-src": new Set(["'self'", "'unsafe-inline'", "https:"]),
        "img-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "font-src": new Set(["'self'", "data:", "https:"]),
        "connect-src": new Set(["'self'", "https:"]),
        "media-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "worker-src": new Set(["'self'", "blob:"]),
        "frame-src": new Set(["'self'"]),
        "form-action": new Set(["'self'"]),
    };
}

/* ---------- HTML / CSS / JS 解析 ---------- */
function parseHTML(html, baseURL, policy, { mode }) {
    const { document: doc } = new JSDOM(html, { url: baseURL }).window;

    doc.querySelectorAll('script[src]').forEach(el => addOrigin(policy['script-src'], el.src, baseURL));
    doc.querySelectorAll('link[rel="stylesheet"]').forEach(el => addOrigin(policy['style-src'], el.href, baseURL));
    doc.querySelectorAll('img[src]').forEach(el => addOrigin(policy['img-src'], el.src, baseURL));
    doc.querySelectorAll('audio[src], video[src], source[src]').forEach(el => addOrigin(policy['media-src'], el.src, baseURL));
    doc.querySelectorAll('iframe[src]').forEach(el => addOrigin(policy['frame-src'], el.src, baseURL));
    doc.querySelectorAll('form[action]').forEach(el => addOrigin(policy['form-action'], el.action, baseURL));

    if (mode !== 'nonce') {
        // compat: インライン script はハッシュで許可
        [...doc.querySelectorAll('script:not([src])')].forEach(s => {
            const code = s.textContent || '';
            if (code.trim()) policy['script-src'].add(`'sha256-${sha256(code)}'`);
        });
    }
    return policy;
}

async function parseCSS(html, baseURL, policy) {
    const { document: doc } = new JSDOM(html, { url: baseURL }).window;
    const links = [...doc.querySelectorAll('link[rel="stylesheet"]')].map(l => l.href);
    const cssTexts = await Promise.all(links.map(u => axios.get(u).then(r => r.data).catch(() => '')));

    const walk = (css) => {
        if (!css) return;
        const ast = csstree.parse(css, { parseAtrulePrelude: true, parseRulePrelude: true });
        csstree.walk(ast, (n) => {
            if (n.type === 'Url') {
                const raw = String(n.value).replace(/['"]/g, '');
                addOrigin(policy['img-src'], raw, baseURL);
                addOrigin(policy['font-src'], raw, baseURL);
            }
        });
    };
    cssTexts.forEach(walk);
    doc.querySelectorAll('style').forEach(s => walk(s.textContent || ''));
    return policy;
}

function parseJSIntoPolicy(policy, jsCode, baseURL) {
    if (!jsCode) return;
    const ast = espree.parse(jsCode, { ecmaVersion: 'latest', sourceType: 'module' });
    estraverse.traverse(ast, {
        enter(node) {
            if (node.type === 'CallExpression') {
                const callee = node.callee;
                const a0 = node.arguments?.[0];
                const lit = (a0?.type === 'Literal' && typeof a0.value === 'string') ? a0.value : null;
                if (callee?.type === 'Identifier' && callee.name === 'fetch' && lit) addOrigin(policy['connect-src'], lit, baseURL);
                if (callee?.type === 'MemberExpression' && callee.object?.name === 'axios' && lit) addOrigin(policy['connect-src'], lit, baseURL);
            }
            if (node.type === 'NewExpression' && node.callee?.name === 'WebSocket') {
                const a0 = node.arguments?.[0];
                if (a0?.type === 'Literal' && typeof a0.value === 'string') addOrigin(policy['connect-src'], a0.value, baseURL);
            }
            if (node.type === 'ImportExpression') {
                const src = node.source;
                if (src?.type === 'Literal' && typeof src.value === 'string') addOrigin(policy['script-src'], src.value, baseURL);
            }
            if (node.type === 'AssignmentExpression'
                && node.left?.type === 'MemberExpression'
                && node.left.property?.name === 'src'
                && node.right?.type === 'Literal'
                && typeof node.right.value === 'string') {
                addOrigin(policy['script-src'], node.right.value, baseURL);
                addOrigin(policy['img-src'], node.right.value, baseURL);
            }
        }
    });
}

function stringify(policy, { reportUri = '/csp-report' } = {}) {
    const map = { ...policy, 'report-uri': new Set([reportUri]) };
    return Object.entries(map).map(([d, vals]) => `${d} ${[...vals].join(' ')};`).join(' ');
}

/* ---------- メインAPI ---------- */
/**
 * opts:
 *  - mode: 'compat' | 'nonce'  (default 'compat')
 *  - nonce: string (mode='nonce' の時に利用)
 *  - reportUri: string
 *  - addReportOnly: boolean  ← 監視用ヘッダも同時に返す
 */
export async function generateCSP(url, html, opts = {}) {
    const mode = opts.mode ?? 'compat';
    const nonce = mode === 'nonce' ? (opts.nonce || randomBytes(16).toString('base64')) : undefined;

    let policy = (mode === 'nonce') ? basePolicyNonce(nonce) : basePolicyCompat();

    policy = parseHTML(html, url, policy, { mode });
    policy = await parseCSS(html, url, policy);

    const { document: doc } = new JSDOM(html, { url }).window;
    for (const s of doc.querySelectorAll('script:not([src])')) {
        parseJSIntoPolicy(policy, s.textContent || '', url);
    }
    const srcs = [...doc.querySelectorAll('script[src]')].map(sc => sc.src);
    const jsList = await Promise.all(srcs.map(u => axios.get(u).then(r => r.data).catch(() => null)));
    jsList.forEach(js => parseJSIntoPolicy(policy, js || '', url));

    const header = stringify(policy, { reportUri: opts.reportUri ?? '/csp-report' });

    return {
        enforceHeader: header,                                 // 常に強制ヘッダ用を返す
        reportOnlyHeader: opts.addReportOnly ? header : null,  // 監視を出したい時だけ
        nonce
    };
}

/* CLI (任意) */
if (import.meta.url === `file://${process.argv[1]}`) {
    const target = process.argv[2];
    if (!target) {
        console.error('Usage: node csp-generator.mjs <URL>');
        process.exit(1);
    }
    const html = await (await fetch(target)).text();
    const { enforceHeader } = await generateCSP(target, html, { mode: 'compat' });
    console.log('--- CSP ---\n' + enforceHeader);
}

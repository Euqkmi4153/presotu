/* csp-generator.mjs — CSP strict/nonce モード（XSS防止） */
import { JSDOM } from 'jsdom';
import axios from 'axios';
import * as csstree from 'css-tree';
import * as espree from 'espree';
import estraverse from 'estraverse';
import { randomBytes } from 'crypto';

/* ---------- utils ---------- */
function addOrigin(set, raw, baseURL) {
    try {
        const u = new URL(raw, baseURL);
        if (u.protocol === 'http:' || u.protocol === 'https:') set.add(u.origin);
        else if (u.protocol === 'ws:' || u.protocol === 'wss:') {
            set.add((u.protocol === 'wss:' ? 'https:' : 'http:') + '//' + u.host);
        }
    } catch { }
}

const deepClonePolicy = (p) =>
    Object.fromEntries(Object.entries(p).map(([k, v]) => [k, new Set(v)]));

/* ---------- base policy (STRICT) ---------- */
function basePolicyNonce(nonce) {
    return {
        "default-src": new Set(["'self'"]),
        "script-src": new Set(["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"]),
        "script-src-elem": new Set(["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"]),
        "script-src-attr": new Set([]),               // ← on* 属性は一切許可しない
        "style-src": new Set(["'self'", "https:"]),   // unsafe-inline 不可
        "img-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "font-src": new Set(["'self'", "data:", "https:"]),
        "connect-src": new Set(["'self'", "https:"]),
        "media-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "worker-src": new Set(["'self'", "blob:"]),
        "frame-src": new Set(["'self'"]),
        "object-src": new Set(["'none'"]),             // ← object/embed/applet 完全禁止
        "form-action": new Set(["'self'"]),
        "base-uri": new Set(["'self'"]),
    };
}

/* ---------- HTML / CSS / JS 解析（許可拡張のみ、危険要素は許可しない） ---------- */
function parseHTML(html, baseURL, policy) {
    const { document: doc } = new JSDOM(html, { url: baseURL }).window;

    // 外部リソースのみ追加（inline / on* は無視）
    doc.querySelectorAll('script[src]').forEach(el =>
        addOrigin(policy['script-src'], el.src, baseURL)
    );
    doc.querySelectorAll('link[rel="stylesheet"]').forEach(el =>
        addOrigin(policy['style-src'], el.href, baseURL)
    );
    doc.querySelectorAll('img[src]').forEach(el =>
        addOrigin(policy['img-src'], el.src, baseURL)
    );
    doc.querySelectorAll('audio[src], video[src], source[src]').forEach(el =>
        addOrigin(policy['media-src'], el.src, baseURL)
    );
    doc.querySelectorAll('iframe[src]').forEach(el =>
        addOrigin(policy['frame-src'], el.src, baseURL)
    );
    doc.querySelectorAll('form[action]').forEach(el =>
        addOrigin(policy['form-action'], el.action, baseURL)
    );

    return policy;
}

async function parseCSS(html, baseURL, policy) {
    const { document: doc } = new JSDOM(html, { url: baseURL }).window;
    const links = [...doc.querySelectorAll('link[rel="stylesheet"]')].map(l => l.href);
    const cssTexts = await Promise.all(
        links.map(u => axios.get(u).then(r => r.data).catch(() => ''))
    );

    const walk = (css) => {
        if (!css) return;
        const ast = csstree.parse(css);
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
                if (callee?.type === 'Identifier' && callee.name === 'fetch' && lit)
                    addOrigin(policy['connect-src'], lit, baseURL);
            }
            if (node.type === 'NewExpression' && node.callee?.name === 'WebSocket') {
                const a0 = node.arguments?.[0];
                if (a0?.type === 'Literal' && typeof a0.value === 'string')
                    addOrigin(policy['connect-src'], a0.value, baseURL);
            }
        }
    });
}

function stringify(policy, { reportUri = '/csp-report' } = {}) {
    const map = { ...policy, 'report-uri': new Set([reportUri]) };
    const order = Object.keys(map).sort();
    return order.map(d => `${d} ${[...map[d]].join(' ')};`).join(' ');
}

/* ---------- main API ---------- */
export async function generateCSP(url, html, opts = {}) {
    const nonce = opts.nonce || randomBytes(16).toString('base64');

    let enforce = basePolicyNonce(nonce);
    enforce = parseHTML(html, url, enforce);
    enforce = await parseCSS(html, url, enforce);

    const { document: doc } = new JSDOM(html, { url }).window;
    for (const s of doc.querySelectorAll('script[src]')) {
        try {
            const js = await axios.get(s.src).then(r => r.data);
            parseJSIntoPolicy(enforce, js, url);
        } catch { }
    }

    const enforceHeader = stringify(enforce, { reportUri: opts.reportUri });

    let reportOnlyHeader = null;
    if (opts.addReportOnly) {
        const ro = deepClonePolicy(enforce);
        ro["require-trusted-types-for"] = new Set(["'script'"]);
        ro["trusted-types"] = new Set(["default"]);
        reportOnlyHeader = stringify(ro, { reportUri: opts.reportUri });
    }

    return { enforceHeader, reportOnlyHeader, nonce };
}

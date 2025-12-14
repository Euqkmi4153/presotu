/* csp-generator.mjs — CSP自動構成（compat: SHA-256 + 'unsafe-hashes'／nonce不要） */
// 最新版はこれ
import { JSDOM } from 'jsdom';
import axios from 'axios';
import * as csstree from 'css-tree';
import * as espree from 'espree';
import estraverse from 'estraverse';
import { createHash, randomBytes } from 'crypto';

const sha256 = (s) => createHash('sha256').update(s).digest('base64');

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

/* ---------- base policies ---------- */
function basePolicyCompat() {
    return {
        "default-src": new Set(["'self'"]),
        "script-src": new Set(["'self'", "https:", "'strict-dynamic'"]),
        // 細分化ディレクティブ
        "script-src-elem": new Set(["'self'", "https:", "'strict-dynamic'"]),
        "script-src-attr": new Set(["'self'"]),
        "style-src": new Set(["'self'", "'unsafe-inline'", "https:"]),
        "img-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "font-src": new Set(["'self'", "data:", "https:"]),
        "connect-src": new Set(["'self'", "https:"]),
        "media-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "worker-src": new Set(["'self'", "blob:"]),
        "frame-src": new Set(["'self'"]),
        "object-src": new Set(["'self'"]),
        "form-action": new Set(["'self'"]),
    };
}
function basePolicyNonce(nonce) {
    return {
        "default-src": new Set(["'self'"]),
        "script-src": new Set(["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"]),
        "script-src-elem": new Set(["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"]),
        "script-src-attr": new Set(["'self'"]),
        "style-src": new Set(["'self'", "'unsafe-inline'", "https:"]),
        "img-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "font-src": new Set(["'self'", "data:", "https:"]),
        "connect-src": new Set(["'self'", "https:"]),
        "media-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "worker-src": new Set(["'self'", "blob:"]),
        "frame-src": new Set(["'self'"]),
        "object-src": new Set(["'self'"]),
        "form-action": new Set(["'self'"]),
    };
}

/* ---------- inline script hashing helpers ---------- */
function* extractRawInlineScripts(html) {
    const re = /<script\b([^>]*?)>([\s\S]*?)<\/script\s*>/gi;
    let m; while ((m = re.exec(html)) !== null) {
        const attrs = m[1] || '';
        if (/\bsrc\s*=/.test(attrs)) continue;
        yield m[2] ?? '';
    }
}
function variantsForHashing(s) {
    const out = new Set();
    const noBOM = s.replace(/^\uFEFF/, '');
    const lf = noBOM.replace(/\r\n/g, '\n');
    const flip = (x) => (x.endsWith('\n') ? x.slice(0, -1) : x + '\n');
    [noBOM, lf, flip(noBOM), flip(lf)].forEach(x => { if (x.length > 0) out.add(x); });
    return [...out];
}

/* ---------- HTML / CSS / JS 解析 ---------- */
function parseHTML(html, baseURL, policy, { mode }) {
    const { document: doc } = new JSDOM(html, { url: baseURL }).window;

    // 外部リソース
    doc.querySelectorAll('script[src]').forEach(el => addOrigin(policy['script-src'], el.src, baseURL));
    doc.querySelectorAll('link[rel="stylesheet"]').forEach(el => addOrigin(policy['style-src'], el.href, baseURL));
    doc.querySelectorAll('img[src]').forEach(el => addOrigin(policy['img-src'], el.src, baseURL));
    doc.querySelectorAll('audio[src], video[src], source[src]').forEach(el => addOrigin(policy['media-src'], el.src, baseURL));
    doc.querySelectorAll('iframe[src]').forEach(el => addOrigin(policy['frame-src'], el.src, baseURL));
    doc.querySelectorAll('form[action]').forEach(el => addOrigin(policy['form-action'], el.action, baseURL));
    // object/embed
    doc.querySelectorAll('object[data]').forEach(el => { addOrigin(policy['object-src'], el.data, baseURL); addOrigin(policy['frame-src'], el.data, baseURL); });
    doc.querySelectorAll('embed[src]').forEach(el => { addOrigin(policy['object-src'], el.src, baseURL); addOrigin(policy['frame-src'], el.src, baseURL); });

    // ① インライン <script> → script-src/script-src-elem にハッシュ
    if (mode !== 'nonce') {
        for (const raw of extractRawInlineScripts(html)) {
            for (const v of variantsForHashing(raw)) {
                const h = `'sha256-${sha256(v)}'`;
                policy['script-src'].add(h);
                policy['script-src-elem'].add(h);
            }
        }
        for (const s of doc.querySelectorAll('script:not([src])')) {
            const code = s.textContent ?? '';
            for (const v of variantsForHashing(code)) {
                const h = `'sha256-${sha256(v)}'`;
                policy['script-src'].add(h);
                policy['script-src-elem'].add(h);
            }
        }
    }

    // ② on* 属性 → script-src-attr にハッシュ + 'unsafe-hashes'
    if (mode !== 'nonce') {
        for (const el of doc.querySelectorAll('*')) {
            for (const attr of el.attributes) {
                if (/^on/i.test(attr.name)) {
                    const raw = attr.value ?? '';
                    if (!raw) continue;
                    const h1 = `'sha256-${sha256(raw)}'`;
                    policy['script-src-attr'].add(h1);
                    policy['script-src'].add(h1); // 互換
                    const t = raw.trim();
                    if (t && t !== raw) {
                        const h2 = `'sha256-${sha256(t)}'`;
                        policy['script-src-attr'].add(h2);
                        policy['script-src'].add(h2);
                    }
                }
            }
        }
        policy['script-src'].add("'unsafe-hashes'");
        policy['script-src-attr'].add("'unsafe-hashes'");
    }

    // ③ Dev origin 自動許可（localhost:ポート）
    const DEV_RE = /\bhttps?:\/\/(?:localhost|127\.0\.0\.1):\d+(?:[\/?#][^\s"'<>]*)?/gi;
    const addDev = (text) => {
        if (!text) return;
        const seen = new Set();
        for (const m of text.matchAll(DEV_RE)) {
            try {
                const u = new URL(m[0], baseURL), origin = u.origin;
                if (seen.has(origin)) continue; seen.add(origin);
                policy['script-src'].add(origin);
                policy['connect-src'].add(origin);
            } catch { }
        }
    };
    addDev(html);
    doc.querySelectorAll('script:not([src])').forEach(s => addDev(s.textContent || ''));

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
    const order = Object.keys(map).sort();
    return order.map((d) => `${d} ${[...map[d]].join(' ')};`).join(' ');
}

/* ---------- main API ---------- */
export async function generateCSP(url, html, opts = {}) {
    const mode = opts.mode ?? 'compat';
    const nonce = mode === 'nonce' ? (opts.nonce || randomBytes(16).toString('base64')) : undefined;

    let enforce = (mode === 'nonce') ? basePolicyNonce(nonce) : basePolicyCompat();
    enforce = parseHTML(html, url, enforce, { mode });
    enforce = await parseCSS(html, url, enforce);

    const { document: doc } = new JSDOM(html, { url }).window;
    for (const s of doc.querySelectorAll('script:not([src])')) {
        parseJSIntoPolicy(enforce, (s.textContent || ''), url);
    }
    const srcs = [...doc.querySelectorAll('script[src]')].map(sc => sc.src);
    const jsList = await Promise.all(srcs.map(u => axios.get(u).then(r => r.data).catch(() => null)));
    jsList.forEach(js => parseJSIntoPolicy(enforce, js || '', url));

    const enforceHeader = stringify(enforce, { reportUri: opts.reportUri ?? '/csp-report' });

    let reportOnlyHeader = null;
    if (opts.addReportOnly) {
        const style = opts.reportOnlyStyle ?? 'monitor';
        let ro = deepClonePolicy(enforce);
        if (style === 'monitor' || style === 'relaxed') {
            ro["require-trusted-types-for"] = new Set(["'script'"]);
            ro["trusted-types"] = new Set(["default"]);
            ro["script-src"].add("'unsafe-inline'");
            ro["script-src"].add("'unsafe-eval'");
            ro["script-src"].add("data:");
            ro["script-src"].add("https:");
            if (style === 'relaxed') {
                ro["style-src"].add("'unsafe-inline'");
                ro["img-src"].add("*");
                ro["connect-src"].add("https:");
            }
        }
        reportOnlyHeader = stringify(ro, { reportUri: opts.reportUri ?? '/csp-report' });
    }

    return { enforceHeader, reportOnlyHeader, nonce };
}

/* CLI (optional) */
if (import.meta.url === `file://${process.argv[1]}`) {
    const target = process.argv[2];
    if (!target) { console.error('Usage: node csp-generator.mjs <URL>'); process.exit(1); }
    const html = await (await fetch(target)).text();
    const { enforceHeader, reportOnlyHeader } =
        await generateCSP(target, html, { mode: 'compat', addReportOnly: true, reportOnlyStyle: 'monitor' });
    console.log('--- CSP ---\n' + enforceHeader);
    console.log('--- CSP-Report-Only ---\n' + reportOnlyHeader);
}

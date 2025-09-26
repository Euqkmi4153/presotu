/* csp-generator.mjs
   ----------------------------------------------------------
   指定された HTML とその URL を解析し、安全に使える
   “Content‑Security‑Policy: …” ヘッダー文字列を返す
   ---------------------------------------------------------- */
import { JSDOM } from 'jsdom';
import axios from 'axios';
import * as csstree from 'css-tree';
import * as espree from 'espree';
import estraverse from 'estraverse';
import { createHash } from 'crypto';

/* ---------- HTML タグ解析 ---------- */
function parseHTML(html, baseURL) {
    const csp = {
        'default-src': new Set(["'self'"]),
        'script-src': new Set(["'self'"]),
        'style-src': new Set(["'self'"]),
        'img-src': new Set(["'self'"]),
        'connect-src': new Set(["'self'"]),
        'form-action': new Set(["'self'"]),
        'frame-src': new Set(["'self'"]),
    };
    const { document: doc } = new JSDOM(html, { url: baseURL }).window;

    /* インライン <script> → SHA‑256 ハッシュ */
    doc.querySelectorAll('script:not([src])').forEach(s => {
        const hash = createHash('sha256').update(s.textContent).digest('base64');
        csp['script-src'].add(`'sha256-${hash}'`);
        csp['script-src'].add("'strict-dynamic'");
        csp['script-src'].add("'unsafe-hashes'");
    });

    /* 外部リソース origin 収集 */
    doc.querySelectorAll('script[src]')
        .forEach(el => addOrigin(csp['script-src'], el.src, baseURL));
    doc.querySelectorAll('link[rel="stylesheet"]')
        .forEach(el => addOrigin(csp['style-src'], el.href, baseURL));
    doc.querySelectorAll('img[src]')
        .forEach(el => addOrigin(csp['img-src'], el.src, baseURL));
    doc.querySelectorAll('form[action]')
        .forEach(el => addOrigin(csp['form-action'], el.action, baseURL));
    doc.querySelectorAll('iframe[src]')
        .forEach(el => addOrigin(csp['frame-src'], el.src, baseURL));

    return csp;
}

function addOrigin(set, raw, baseURL) {
    try {
        const u = new URL(raw, baseURL);
        // http / https だけを CSP に載せる（data:, blob:, about: などは無視）
        if (u.protocol === 'http:' || u.protocol === 'https:') set.add(u.origin);
    } catch {
        // console.debug('[CSP] skip invalid URL:', raw);
    }
}


/* ---------- CSS 内 URL() ---------- */
async function parseCSS(html, baseURL) {
    const set = new Set();
    const { document: doc } = new JSDOM(html, { url: baseURL }).window;

    const links = [...doc.querySelectorAll('link[rel="stylesheet"]')].map(l => l.href);
    const cssTexts = await Promise.all(
        links.map(u => axios.get(u).then(r => r.data).catch(() => '')));

    const addUrl = raw => addOrigin(set, raw, baseURL);

    const walkCss = text => {
        const ast = csstree.parse(text);
        csstree.walk(ast, { visit: 'Url', enter: n => addUrl(n.value.replace(/['"]/g, '')) });
    };
    cssTexts.forEach(walkCss);
    doc.querySelectorAll('style').forEach(s => walkCss(s.textContent));

    return set;
}

/* ---------- JavaScript 動的解析 (fetch / import()) ---------- */
async function parseJS(csp, code, baseURL) {
    const ast = espree.parse(code, { ecmaVersion: 'latest', sourceType: 'module' });
    estraverse.traverse(ast, {
        enter(node) {
            if (node.type === 'CallExpression' && node.callee.name === 'fetch') {
                const arg = node.arguments[0];
                if (arg?.type === 'Literal')
                    addOrigin(csp['connect-src'], arg.value, baseURL);
            }
            if (node.type === 'ImportExpression') {
                addOrigin(csp['script-src'], node.source.value, baseURL);
            }
        }
    });
}

/* ---------- 文字列化 ---------- */
function stringifyCSP(map) {
    map['report-uri'] = new Set(['/csp-report']);
    return Object.entries(map)
        .map(([d, vals]) => `${d} ${[...vals].join(' ')};`)
        .join(' ');
}

/* ---------- メイン API ---------- */
export async function generateCSP(url, html) {
    const map = parseHTML(html, url);

    (await parseCSS(html, url)).forEach(o => map['img-src'].add(o));

    const { document: doc } = new JSDOM(html, { url }).window;
    for (const s of doc.querySelectorAll('script:not([src])'))
        await parseJS(map, s.textContent, url);
    await Promise.all(
        [...doc.querySelectorAll('script[src]')].map(async sc => {
            const js = await axios.get(sc.src).then(r => r.data).catch(() => null);
            if (js) await parseJS(map, js, url);
        })
    );


    return stringifyCSP(map);
}


// ── 直接実行されたときだけ動く CLI ラッパー ──────────
if (import.meta.url === `file://${process.argv[1]}`) {
    const target = process.argv[2];
    if (!target) {
        console.error('Usage: node csp‑generator.mjs <URL>');
        process.exit(1);
    }

    /* 1. HTML を取得（Node18+ の fetch を使用） */
    const html = await (await fetch(target)).text();

    /* 2. CSP を生成して出力 */
    const cspHeader = await generateCSP(target, html);
    console.log('--- Generated CSP Header ---');
    console.log(cspHeader);
}
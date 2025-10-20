/* csp-generator.mjs  — “壊さず守る”互換モードをデフォルトに */
import { JSDOM } from 'jsdom';
import axios from 'axios';
import * as csstree from 'css-tree';
import * as espree from 'espree';
import estraverse from 'estraverse';
import { createHash, randomBytes } from 'crypto';

/* ===== ユーティリティ ===== */
function addOrigin(set, raw, baseURL) {
    try {
        const u = new URL(raw, baseURL);
        if (u.protocol === 'http:' || u.protocol === 'https:') {
            set.add(u.origin);
        } else if (u.protocol === 'ws:' || u.protocol === 'wss:') {
            // CSP は origin 表記。wss/ws は https/http に丸める
            set.add((u.protocol === 'wss:' ? 'https:' : 'http:') + '//' + u.host);
        } else if (u.protocol === 'data:' || u.protocol === 'blob:') {
            // data/blob は一部ディレクティブで許す（後段でまとめて付与）
        }
    } catch { /* noop */ }
}
const sha256 = (s) => createHash('sha256').update(s).digest('base64');

/* ===== 初期ポリシー（互換寄り） ===== */
function basePolicyCompat() {
    return {
        "default-src": new Set(["'self'"]),
        "script-src": new Set(["'self'", "https:"]), // CDN を壊しにくく
        "style-src": new Set(["'self'", "'unsafe-inline'", "https:"]), // inline style を許容
        "img-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "font-src": new Set(["'self'", "data:", "https:"]),
        "connect-src": new Set(["'self'", "https:"]),
        "media-src": new Set(["'self'", "data:", "blob:", "https:"]),
        "worker-src": new Set(["'self'", "blob:"]),
        "frame-src": new Set(["'self'"]),
        "form-action": new Set(["'self'"]),
    };
}

/* ===== 初期ポリシー（nonce + strict-dynamic）===== */
function basePolicyNonce(nonce) {
    return {
        "default-src": new Set(["'self'"]),
        "script-src": new Set(["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"]), // ホスト許可より nonce を優先
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

/* ===== HTML 解析 ===== */
function parseHTML(html, baseURL, policy, { mode, nonce }) {
    const { document: doc } = new JSDOM(html, { url: baseURL }).window;

    // 外部リソース
    doc.querySelectorAll('script[src]').forEach(el => addOrigin(policy['script-src'], el.src, baseURL));
    doc.querySelectorAll('link[rel="stylesheet"]').forEach(el => addOrigin(policy['style-src'], el.href, baseURL));
    doc.querySelectorAll('img[src]').forEach(el => addOrigin(policy['img-src'], el.src, baseURL));
    doc.querySelectorAll('audio[src], video[src], source[src]').forEach(el => addOrigin(policy['media-src'], el.src, baseURL));
    doc.querySelectorAll('iframe[src]').forEach(el => addOrigin(policy['frame-src'], el.src, baseURL));
    doc.querySelectorAll('form[action]').forEach(el => addOrigin(policy['form-action'], el.action, baseURL));

    // インライン <script>
    const inlineScripts = [...doc.querySelectorAll('script:not([src])')];
    if (mode === 'nonce') {
        // nonce モード：CSP 側に `'nonce-…'` を入れている想定。HTML の書き換えは呼び出し側で実施。
        // ここではヘッダ側の準備のみ（nonce は basePolicyNonce 渡し済み）
    } else {
        // compat モード：インラインはハッシュで許可（strict-dynamic は付けない）
        inlineScripts.forEach(s => {
            const code = s.textContent || '';
            if (code.trim()) policy['script-src'].add(`'sha256-${sha256(code)}'`);
        });
    }

    return policy;
}

/* ===== CSS 解析（url() からオリジン収集）===== */
async function parseCSS(html, baseURL, policy) {
    const { document: doc } = new JSDOM(html, { url: baseURL }).window;

    // 外部 CSS を取得
    const links = [...doc.querySelectorAll('link[rel="stylesheet"]')].map(l => l.href);
    const cssTexts = await Promise.all(links.map(u => axios.get(u).then(r => r.data).catch(() => '')));

    const walkCss = (text) => {
        if (!text) return;
        const ast = csstree.parse(text, { parseAtrulePrelude: true, parseRulePrelude: true });
        csstree.walk(ast, (n) => {
            if (n.type === 'Url') {
                const raw = String(n.value).replace(/['"]/g, '');
                // フォント/画像/メディアいずれにも使われ得るので、ひとまず img-src/font-src へ
                addOrigin(policy['img-src'], raw, baseURL);
                addOrigin(policy['font-src'], raw, baseURL);
            }
        });
    };

    cssTexts.forEach(walkCss);
    // <style> 内も
    doc.querySelectorAll('style').forEach(s => walkCss(s.textContent || ''));

    return policy;
}

/* ===== JS 解析（fetch/import/WebSocket/src など）===== */
function parseJSIntoPolicy(policy, jsCode, baseURL) {
    if (!jsCode) return;
    const ast = espree.parse(jsCode, { ecmaVersion: 'latest', sourceType: 'module' });

    estraverse.traverse(ast, {
        enter(node) {
            // fetch('https://...'), axios.get/post('https://...')
            if (node.type === 'CallExpression') {
                const callee = node.callee;
                const firstArg = node.arguments?.[0];
                const lit = (firstArg && firstArg.type === 'Literal' && typeof firstArg.value === 'string') ? firstArg.value : null;

                // fetch(...)
                if (callee?.type === 'Identifier' && callee.name === 'fetch' && lit) {
                    addOrigin(policy['connect-src'], lit, baseURL);
                }
                // axios.get/post(...)
                if (callee?.type === 'MemberExpression' && callee.object?.name === 'axios' && lit) {
                    addOrigin(policy['connect-src'], lit, baseURL);
                }
            }

            // new WebSocket('wss://...')
            if (node.type === 'NewExpression' && node.callee?.name === 'WebSocket') {
                const arg = node.arguments?.[0];
                if (arg?.type === 'Literal' && typeof arg.value === 'string') {
                    addOrigin(policy['connect-src'], arg.value, baseURL);
                }
            }

            // import('https://...')
            if (node.type === 'ImportExpression') {
                const src = node.source;
                if (src?.type === 'Literal' && typeof src.value === 'string') {
                    addOrigin(policy['script-src'], src.value, baseURL);
                }
            }

            // element.src = 'https://...'（保守的：script/img の両方へ）
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

/* ===== 文字列化 ===== */
function stringify(policy, { reportUri = '/csp-report' } = {}) {
    const map = { ...policy, 'report-uri': new Set([reportUri]) };
    return Object.entries(map)
        .map(([d, vals]) => `${d} ${[...vals].join(' ')};`)
        .join(' ');
}

/* ===== メイン API =====
 * opts:
 *   mode: 'compat' | 'nonce'  （既定: 'compat'）
 *   nonce: string             （mode='nonce' のとき必須。HTML側で全 <script> に同一 nonce を付与すること）
 *   reportOnly: boolean       （true ならヘッダ名は 'Content-Security-Policy-Report-Only' として使うとよい）
 *   reportUri: string
 */
export async function generateCSP(url, html, opts = {}) {
    const mode = opts.mode ?? 'compat';
    const nonce = mode === 'nonce' ? (opts.nonce || randomBytes(16).toString('base64')) : undefined;

    // 初期ポリシー
    let policy = (mode === 'nonce') ? basePolicyNonce(nonce) : basePolicyCompat();

    // HTML からリソース抽出（インライン script 対応含む）
    policy = parseHTML(html, url, policy, { mode, nonce });

    // CSS から url() を抽出
    policy = await parseCSS(html, url, policy);

    // JS 解析：インラインと外部 src の中身
    const { document: doc } = new JSDOM(html, { url }).window;

    // インライン
    for (const s of doc.querySelectorAll('script:not([src])')) {
        parseJSIntoPolicy(policy, s.textContent || '', url);
    }

    // 外部
    const srcs = [...doc.querySelectorAll('script[src]')].map(sc => sc.src);
    const jsList = await Promise.all(srcs.map(u => axios.get(u).then(r => r.data).catch(() => null)));
    jsList.forEach(js => parseJSIntoPolicy(policy, js || '', url));

    // 文字列化（ヘッダ本文）
    const header = stringify(policy, { reportUri: opts.reportUri ?? '/csp-report' });

    // 返り値：ヘッダ文字列と（nonce モードのとき）nonce を併せて返しておく
    return { header, nonce };
}

/* === CLI: 互換モードで実行（従来の動作互換）=== */
if (import.meta.url === `file://${process.argv[1]}`) {
    const target = process.argv[2];
    if (!target) {
        console.error('Usage: node csp-generator.mjs <URL>');
        process.exit(1);
    }
    const html = await (await fetch(target)).text();
    const { header } = await generateCSP(target, html, { mode: 'compat' });
    console.log('--- Generated CSP Header ---');
    console.log(header);
}

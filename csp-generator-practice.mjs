// node csp-from-js.mjs ./sample/innerHTML/innerHTML.js https://example.com/page

import fs from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import * as espree from 'espree';
import estraverse from 'estraverse';

/* ========== 小物ユーティリティ ========== */
function addOrigin(set, raw, baseURL) {
    try {
        const u = new URL(raw, baseURL);
        if (u.protocol === 'http:' || u.protocol === 'https:' || u.protocol === 'wss:' || u.protocol === 'ws:') {
            // wss/ws は connect-src で https/http と同じ「origin」表記に丸める
            const scheme = (u.protocol === 'wss:' || u.protocol === 'ws:') ? (u.protocol === 'wss:' ? 'https:' : 'http:') : u.protocol;
            const norm = `${scheme}//${u.host}`;
            set.add(norm);
        }
    } catch { /* 無効/相対のときは baseURL 無しだと捨てる */ }
}

function isLiteralURL(node) {
    return node && node.type === 'Literal' && typeof node.value === 'string' && /^(https?:|wss?:|\/)/.test(node.value);
}

function textOfLiteral(node) {
    return node && node.type === 'Literal' ? String(node.value) : null;
}

/* ========== JS 解析 → CSP マップ ========== */
export function generateCSPFromJS(jsCode, { baseURL = 'https://kansai-u.reallyenglish.jp/login' } = {}) {
    // 初期ポリシー（堅めのデフォルト）
    const csp = {
        "default-src": new Set(["'self'"]),
        "object-src": new Set(["'none'"]),
        "base-uri": new Set(["'none'"]),
        "script-src": new Set(["'self'"]),
        "style-src": new Set(["'self'"]),
        "img-src": new Set(["'self'", "data:", "blob:"]),
        "connect-src": new Set(["'self'"]),
        "frame-src": new Set(["'self'"]),
        // 任意：レポート送付先（必要なら差し替え）
        "report-uri": new Set(['/csp-report']),
    };

    let needsTrustedTypes = false;    // innerHTML 等の危険シンク検出フラグ
    let sawDynamicScript = false;     // import() などで strict-dynamic 推奨

    const ast = espree.parse(jsCode, {
        ecmaVersion: 'latest',
        sourceType: 'script',      // 必要に応じ 'module'
    });

    estraverse.traverse(ast, {
        enter(node, parent) {
            /* --------- ネットワーク系: connect-src --------- */
            // fetch("..."), axios.get("..."), new WebSocket("wss://...")
            if (node.type === 'CallExpression') {
                // fetch(...)
                if (node.callee.type === 'Identifier' && node.callee.name === 'fetch') {
                    const raw = textOfLiteral(node.arguments[0]);
                    if (raw) addOrigin(csp['connect-src'], raw, baseURL);
                }
                // axios.get('https://...') / axios.post('https://...')
                if (node.callee.type === 'MemberExpression' &&
                    node.callee.object?.name === 'axios' &&
                    node.arguments?.length > 0) {
                    const raw = textOfLiteral(node.arguments[0]);
                    if (raw) addOrigin(csp['connect-src'], raw, baseURL);
                }
            }
            if (node.type === 'NewExpression' && node.callee?.name === 'WebSocket') {
                const raw = textOfLiteral(node.arguments[0]);
                if (raw) addOrigin(csp['connect-src'], raw, baseURL);
            }

            /* --------- 動的 import(): script-src --------- */
            if (node.type === 'ImportExpression') {
                const raw = textOfLiteral(node.source);
                if (raw) addOrigin(csp['script-src'], raw, baseURL);
                sawDynamicScript = true;
            }

            /* --------- <script src=...> 動的生成: script-src --------- */
            // document.createElement('script') の検出
            if (node.type === 'CallExpression' &&
                node.callee.type === 'MemberExpression' &&
                node.callee.object?.name === 'document' &&
                node.callee.property?.name === 'createElement' &&
                node.arguments?.[0]?.type === 'Literal' &&
                node.arguments[0].value === 'script') {
                // 以後の代入で .src = "https://..." を拾う
                // 厳密には別ノードで起こるので、ここでは「動的スクリプトあり」フラグだけ立てる
                sawDynamicScript = true;
            }

            // x.src = "https://..."（要素種別が不明な時は script/img/iframeを判別できない）
            if (node.type === 'AssignmentExpression' &&
                node.left?.type === 'MemberExpression' &&
                node.left.property?.name === 'src' &&
                isLiteralURL(node.right)) {
                // 安全側に倒して script-src と img-src の両方へ入れておく（過剰なら後で人が削る）
                addOrigin(csp['script-src'], node.right.value, baseURL);
                addOrigin(csp['img-src'], node.right.value, baseURL);
            }

            /* --------- 危険シンク: innerHTML 等 → Trusted Types --------- */
            if (node.type === 'AssignmentExpression' &&
                node.left?.type === 'MemberExpression' &&
                (node.left.property?.name === 'innerHTML' || node.left.property?.name === 'outerHTML')) {
                needsTrustedTypes = true;
            }

            // location.hash の利用（文字列→DOM 代入っぽいコードのヒント）
            if (node.type === 'MemberExpression' &&
                node.object?.type === 'MemberExpression' &&
                node.object.object?.name === 'window' &&
                node.object.property?.name === 'location' &&
                node.property?.name === 'hash') {
                // 直接 CSP には反映しないが、ダイナミック性の指標として strict-dynamic 推奨
                sawDynamicScript = true;
            }
        }
    });

    // 動的ローダがあるなら strict-dynamic / nonce 運用を推奨
    if (sawDynamicScript) {
        csp['script-src'].add("'strict-dynamic'");
        // ここでは “自動発行される” ことを想定して nonce をダミーで付与
        // 実運用ではレスポンス生成側で毎回ランダムに付与する
        csp['script-src'].add("'nonce-__RUNTIME_NONCE__'");
    }

    // innerHTML 等があるなら Trusted Types を要求
    // （CSPヘッダのディレクティブ）
    if (needsTrustedTypes) {
        csp["require-trusted-types-for"] = new Set(["'script'"]);
        // 併せて Trusted-Types ヘッダの設定も別途サーバ側でするのが推奨
        // 例: Trusted-Types: default; policy-name ...
    }

    return csp;
}

/* ========== マップ → ヘッダー文字列 ========== */
export function stringifyCSP(map) {
    return Object.entries(map)
        .map(([dir, vals]) => `${dir} ${[...vals].join(' ')};`)
        .join(' ');
}

/* ========== CLI: JS ファイルを読み、CSP を出力 ========== */
if (import.meta.url === `file://${process.argv[1]}`) {
    const jsPath = process.argv[2];
    const baseURL = process.argv[3] || 'https://example.com/';
    if (!jsPath) {
        console.error('Usage: node csp-from-js.mjs <path/to/script.js> [baseURL]');
        process.exit(1);
    }
    const code = fs.readFileSync(jsPath, 'utf-8');
    const map = generateCSPFromJS(code, { baseURL });
    const header = stringifyCSP(map);
    console.log('--- Generated CSP (from JS) ---');
    console.log(header);
}

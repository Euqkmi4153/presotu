// summarize_ab_csp.mjs
// A/B (baseline vs enforce) の JSONL を突き合わせて CSP遮断率を集計する。
// - 分母: baselineで fired=true のレコード数（= 実行可能 payload）
// - 分子: baselineで fired=true かつ enforceで fired=false かつ enforce側で CSP violation が観測された数
// さらに directive（effectiveDirective/violatedDirective/normalized directive）別の内訳も集計する。
//
// Usage:
//   node summarize_ab_csp.mjs <baseline.jsonl> <enforce.jsonl> [--out summary.json]
// Example:
//   node summarize_ab_csp.mjs ./results_baseline2.jsonl ./results_enforce2.jsonl --out ./ab_summary.json

import fs from "fs";
import path from "path";

/* ---------- args ---------- */

function parseArgs(argv) {
    const args = { _: [] };
    for (let i = 2; i < argv.length; i++) {
        const a = argv[i];
        if (a === "--out") {
            args.out = argv[++i];
        } else {
            args._.push(a);
        }
    }
    if (args._.length < 2) {
        console.error(
            "Usage: node summarize_ab_csp.mjs <baseline.jsonl> <enforce.jsonl> [--out summary.json]"
        );
        process.exit(1);
    }
    return args;
}

/* ---------- jsonl read ---------- */

function safeJsonParse(line) {
    try {
        return JSON.parse(line);
    } catch {
        return null;
    }
}

function readJsonl(file) {
    const text = fs.readFileSync(file, "utf8");
    const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
    const out = [];
    let bad = 0;
    for (const l of lines) {
        const obj = safeJsonParse(l);
        if (!obj) bad++;
        else out.push(obj);
    }
    return { records: out, badLines: bad, totalLines: lines.length };
}

/* ---------- pairing key ---------- */

function pickKey(r) {
    // 最優先: payloadHash（payloadごとの一意性が高い）
    if (r && typeof r.payloadHash === "string" && r.payloadHash.length > 0) return `h:${r.payloadHash}`;
    // fallback: index
    if (r && typeof r.index === "number") return `i:${r.index}`;
    // worst: payload文字列（重いので最後）
    if (r && typeof r.payload === "string") return `p:${r.payload}`;
    return null;
}

/* ---------- semantics ---------- */

function toBool(x) {
    return x === true;
}

function isNavOk(r) {
    // run_payload_tests.mjs の設計に合わせる:
    // navError が null/空ならOKとみなす
    const e = r?.navError;
    return !(typeof e === "string" && e.length > 0);
}

function hasCspViolation(r) {
    // 現在の results では cspViolations は「配列（文字列 or オブジェクト）」の想定
    const arr = r?.cspViolations;
    if (Array.isArray(arr) && arr.length > 0) return true;

    // 旧形式のログ配列にも一応対応
    const logs = r?.cspViolationsLog;
    if (Array.isArray(logs) && logs.length > 0) return true;

    // 補助フラグがある場合
    if (r?.blockedByCspLikely === true) return true;

    return false;
}

// directive の正規化（必要なら追加でルール拡張）
function normalizeDirective(d) {
    if (!d) return "unknown";
    const s = String(d).trim();
    if (!s) return "unknown";

    // 例: "script-src-elem" は "script-src" と近いが、ここではそのまま残す
    // 研究でまとめたいならここで丸める
    return s;
}

function extractDirectiveCounts(r) {
    // 可能なら事前集計された cspDirectiveCounts を優先
    const d = r?.cspDirectiveCounts;
    if (d && typeof d === "object") {
        const out = {};
        for (const [k, v] of Object.entries(d)) {
            const n = Number(v);
            if (!Number.isFinite(n) || n <= 0) continue;
            const nk = normalizeDirective(k);
            out[nk] = (out[nk] || 0) + n;
        }
        if (Object.keys(out).length > 0) return out;
    }

    // fallback: cspViolations から拾う（配列要素が文字列 or オブジェクトの両方を想定）
    const arr = r?.cspViolations;
    const out = {};
    if (Array.isArray(arr)) {
        for (const v of arr) {
            let key = "unknown";
            if (typeof v === "string") {
                // 文字列ログの場合は雑に directive っぽい部分を拾う
                // 例: "[CSP_VIOLATION] {...\"effectiveDirective\":\"script-src\"...}"
                const m = v.match(/effectiveDirective[:"]\s*([a-z0-9\-]+)/i);
                if (m && m[1]) key = m[1];
            } else if (v && typeof v === "object") {
                key = v.directive || v.effectiveDirective || v.violatedDirective || "unknown";
            }
            key = normalizeDirective(key);
            out[key] = (out[key] || 0) + 1;
        }
    }
    return out;
}

function addCounts(mapObj, countsObj) {
    for (const [k, v] of Object.entries(countsObj || {})) {
        mapObj[k] = (mapObj[k] || 0) + Number(v || 0);
    }
}

/* ---------- pretty print (screenshot style) ---------- */

function fmtNum(n) {
    return String(n ?? 0);
}

function fmtPct(n, d) {
    if (!d) return "0.00%";
    return ((n / d) * 100).toFixed(2) + "%";
}

function printSection(title) {
    console.log("");
    console.log(`[${title}]`);
}

function printKV(label, value, { labelWidth = 28 } = {}) {
    const l = String(label).padEnd(labelWidth, " ");
    console.log(`  ${l} : ${value}`);
}

function printOutcome(icon, label, n, denom, { labelWidth = 28 } = {}) {
    const l = String(label).padEnd(labelWidth, " ");
    const v = `${fmtNum(n)} (${fmtPct(n, denom)})`;
    console.log(`  ${icon} ${l} : ${v}`);
}

/* ---------- main ---------- */

function main() {
    const args = parseArgs(process.argv);
    const baselinePath = args._[0];
    const enforcePath = args._[1];

    const baseline = readJsonl(baselinePath);
    const enforce = readJsonl(enforcePath);

    const baseMap = new Map();
    const enMap = new Map();

    // 先勝ちで格納（重複キーがあっても最初を採用）
    for (const r of baseline.records) {
        const k = pickKey(r);
        if (!k) continue;
        if (!baseMap.has(k)) baseMap.set(k, r);
    }
    for (const r of enforce.records) {
        const k = pickKey(r);
        if (!k) continue;
        if (!enMap.has(k)) enMap.set(k, r);
    }

    // pairing stats
    let paired = 0;
    let missingInEnforce = 0;
    let missingInBaseline = 0;

    // navigation
    let navOkBoth = 0;
    let navErrEither = 0;

    // denominator + outcomes
    let executableBaseline = 0; // baseline fired true かつ nav ok
    let blockedByCsp = 0;       // baseline fired true かつ enforce fired false かつ enforce cspあり
    let bypassed = 0;           // baseline fired true かつ enforce fired true
    let other = 0;              // baseline fired true だが enforce で CSP信号なし（or 判定不能）

    // directive breakdown（blockedByCsp のみ）
    const directiveHitCounts = {};

    // baselineキー基準で突き合わせ
    for (const [k, b] of baseMap.entries()) {
        const e = enMap.get(k);
        if (!e) {
            missingInEnforce++;
            continue;
        }
        paired++;

        const bNavOk = isNavOk(b);
        const eNavOk = isNavOk(e);

        if (!bNavOk || !eNavOk) {
            navErrEither++;
            continue;
        }
        navOkBoth++;

        const bFired = toBool(b?.fired);
        const eFired = toBool(e?.fired);
        const eHasCsp = hasCspViolation(e);

        // 分母: baselineで実行できた（fired=true）
        if (bFired) {
            executableBaseline++;

            if (eFired) {
                bypassed++;
            } else {
                if (eHasCsp) {
                    blockedByCsp++;
                    addCounts(directiveHitCounts, extractDirectiveCounts(e));
                } else {
                    other++;
                }
            }
        }
    }

    // enforce側だけ存在（参考）
    for (const [k] of enMap.entries()) {
        if (!baseMap.has(k)) missingInBaseline++;
    }

    const denom = executableBaseline;

    // structured summary for saving
    const summary = {
        inputs: {
            baseline: path.resolve(baselinePath),
            enforce: path.resolve(enforcePath),
            baseline_lines: baseline.totalLines,
            baseline_bad_lines: baseline.badLines,
            enforce_lines: enforce.totalLines,
            enforce_bad_lines: enforce.badLines,
        },
        pairing: {
            paired,
            missingInEnforce,
            missingInBaseline,
            navOkBoth,
            navErrEither,
        },
        denominator_definition: "baseline fired=true AND both navigation OK",
        counts: {
            executableBaseline,
            blockedByCsp,
            bypassed,
            other,
        },
        rates: {
            blocked_pct: fmtPct(blockedByCsp, denom),
            bypassed_pct: fmtPct(bypassed, denom),
            other_pct: fmtPct(other, denom),
            denom,
        },
        directive_effectiveness_on_blocked: directiveHitCounts,
        generatedAt: new Date().toISOString(),
    };

    // --- console output (screenshot-like) ---
    console.log("=== CSP Blocking Evaluation (A/B) ===");
    console.log(`Baseline: ${baselinePath}`);
    console.log(`Enforce : ${enforcePath}`);

    if (baseline.badLines || enforce.badLines) {
        console.log(
            `[Warn] bad json lines baseline=${baseline.badLines}/${baseline.totalLines}, enforce=${enforce.badLines}/${enforce.totalLines}`
        );
    }

    printSection("Pairing");
    printKV("Paired records", paired);
    printKV("Missing in enforce", missingInEnforce);
    printKV("Missing in baseline", missingInBaseline);
    printKV("Navigation OK (both)", navOkBoth);
    printKV("Navigation errors (either)", navErrEither);

    printSection("Denominator");
    printKV("Executable baseline (fired)", executableBaseline);

    printSection("Outcomes over executable baseline");
    printOutcome("✅", "Blocked by CSP (observed)", blockedByCsp, denom);
    printOutcome("❌", "Bypassed (still executed)", bypassed, denom);
    printOutcome("⚠️", "Other (no CSP signal)", other, denom);

    printSection("Directive effectiveness (blocked cases only)");
    const entries = Object.entries(directiveHitCounts).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) {
        console.log("  (no directives recorded)");
    } else {
        const w = Math.min(36, Math.max(...entries.slice(0, 30).map(([k]) => k.length)) + 2);
        for (const [d, c] of entries.slice(0, 50)) {
            console.log(`  ${d.padEnd(w, " ")}: ${c}`);
        }
        if (entries.length > 50) console.log(`  ... (${entries.length - 50} more)`);
    }

    // save JSON summary
    if (args.out) {
        fs.writeFileSync(args.out, JSON.stringify(summary, null, 2), "utf8");
        console.log("");
        console.log(`[saved] ${args.out}`);
    }
}

main();

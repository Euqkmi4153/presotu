// summarize_result.mjs (revised)
// Usage:
//   node summarize_result.mjs ./results.jsonl
//   node summarize_result.mjs ./results.jsonl --csv ./summary.csv
//   node summarize_result.mjs ./results.jsonl --top 30
//   node summarize_result.mjs ./results.jsonl --strict
//
// Assumes each line is JSON produced by run_payload_tests.mjs.
// Flexible input tolerated:
//   - rec.cspViolations: array of strings OR objects OR mixed
//   - rec.cspReports:   array of strings OR objects OR mixed (optional)
//   - rec.fired: boolean (XSS hook fired)

import fs from "fs";
import readline from "readline";

const input = process.argv[2];
if (!input || input.startsWith("-")) {
    console.error("Usage: node summarize_result.mjs <results.jsonl> [--csv summary.csv] [--top N] [--strict]");
    process.exit(1);
}

function getArg(flag, def = null) {
    const i = process.argv.indexOf(flag);
    if (i === -1) return def;
    return process.argv[i + 1] ?? def;
}
const csvPath = getArg("--csv", null);
const topN = Number(getArg("--top", "20"));
const strictMode = process.argv.includes("--strict"); // strict: unknownを除外して率を出す用

function safeJsonParse(line) {
    try { return JSON.parse(line); } catch { return null; }
}

/**
 * Normalize CSP violation/report entry to object
 * Accepts:
 *  - object: {effectiveDirective,...}
 *  - string log: "[CSP_VIOLATION] {...}" or JSON string "{...}"
 */
function normalizeCspEvent(entry) {
    if (!entry) return null;

    if (typeof entry === "object") {
        // already structured
        const v = entry;
        return {
            effectiveDirective: v.effectiveDirective ?? null,
            violatedDirective: v.violatedDirective ?? null,
            blockedURI: v.blockedURI ?? v.blockedUri ?? null,
            disposition: v.disposition ?? null,
            sourceFile: v.sourceFile ?? null,
            lineNumber: v.lineNumber ?? null,
            columnNumber: v.columnNumber ?? null,
            statusCode: v.statusCode ?? null,
        };
    }

    if (typeof entry === "string") {
        const s = entry.trim();
        // if log prefix exists, strip to JSON part
        const idx = s.indexOf("{");
        const jsonPart = idx >= 0 ? s.slice(idx) : s;
        const obj = safeJsonParse(jsonPart);
        if (!obj || typeof obj !== "object") return null;
        return normalizeCspEvent(obj);
    }

    return null;
}

function classifyPayload(p) {
    const s = String(p || "").toLowerCase();

    // buckets (卒論向けに最低限“攻撃手段”が分かる程度)
    if (s.includes("<script")) return "inline-script/tag";
    if (s.match(/\bon[a-z]+\s*=/)) return "event-handler";
    if (s.includes("javascript:")) return "javascript-uri";
    if (s.includes("data:")) return "data-uri";
    if (s.includes("<svg") || s.includes("<math")) return "svg/math";
    if (s.includes("<iframe")) return "iframe";
    if (s.includes("<object") || s.includes("<embed") || s.includes("<applet")) return "object/embed/applet";
    if (s.includes("<img") || s.includes("<image")) return "img";
    if (s.includes("<a ") || s.includes("href=")) return "link";
    if (s.includes("<form") || s.includes("formaction=") || s.includes("action=")) return "form";
    if (s.includes("eval(") || s.includes("atob(") || s.includes("\\x") || s.includes("\\u")) return "eval/obfuscation";
    return "other";
}

function inc(map, key, by = 1) {
    map.set(key, (map.get(key) || 0) + by);
}

function pct(n, d) {
    if (!d) return "0.00%";
    return ((n / d) * 100).toFixed(2) + "%";
}

function topEntries(map, n) {
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

/**
 * preventedLikely 判定
 * - fired === true → preventedではない
 * - fired === false かつ CSP violation/report が1件以上 → preventedLikely
 * - fired === false かつ 何も観測なし → unknown
 */
function decideOutcome({ fired, violationsCount, reportsCount }) {
    if (fired) return "fired";
    if ((violationsCount || 0) > 0) return "preventedLikely";
    if ((reportsCount || 0) > 0) return "preventedLikely"; // report-onlyでも検知できたなら「防御(検知)が効いた」扱いにする場合
    return "unknown";
}

// --- aggregates ---
let total = 0;
let fired = 0;
let preventedLikely = 0;
let unknownNoSignal = 0;
let parseErrors = 0;

const directiveCounts = new Map();          // effectiveDirective -> count
const violatedDirectiveCounts = new Map();  // violatedDirective -> count
const blockedUriCounts = new Map();         // blockedURI -> count

const categoryTotals = new Map();
const categoryFired = new Map();
const categoryPrevented = new Map();
const categoryUnknown = new Map();

const examples = {
    fired: [],
    preventedLikely: [],
    unknownNoSignal: [],
};

const fileStream = fs.createReadStream(input, { encoding: "utf8" });
const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

for await (const line of rl) {
    if (!line || !line.trim()) continue;

    const rec = safeJsonParse(line);
    if (!rec) { parseErrors++; continue; }

    total++;
    const payload = rec.payload ?? "";
    const cat = classifyPayload(payload);
    inc(categoryTotals, cat, 1);

    const isFired = !!rec.fired;

    // Normalize CSP events
    const violArrRaw = Array.isArray(rec.cspViolations) ? rec.cspViolations : [];
    const repArrRaw = Array.isArray(rec.cspReports) ? rec.cspReports : []; // optional

    const violObjs = violArrRaw.map(normalizeCspEvent).filter(Boolean);
    const repObjs = repArrRaw.map(normalizeCspEvent).filter(Boolean);

    // Count directives (violation側を優先)
    for (const v of violObjs) {
        if (v.effectiveDirective) inc(directiveCounts, v.effectiveDirective, 1);
        if (v.violatedDirective) inc(violatedDirectiveCounts, v.violatedDirective, 1);
        if (v.blockedURI) inc(blockedUriCounts, v.blockedURI, 1);
    }
    // report-onlyしか無い場合も、分類に活用できるようにカウント
    if (violObjs.length === 0) {
        for (const v of repObjs) {
            if (v.effectiveDirective) inc(directiveCounts, v.effectiveDirective, 1);
            if (v.violatedDirective) inc(violatedDirectiveCounts, v.violatedDirective, 1);
            if (v.blockedURI) inc(blockedUriCounts, v.blockedURI, 1);
        }
    }

    const outcome = decideOutcome({
        fired: isFired,
        violationsCount: violObjs.length,
        reportsCount: repObjs.length,
    });

    if (outcome === "fired") {
        fired++;
        inc(categoryFired, cat, 1);
        if (examples.fired.length < 5) examples.fired.push(payload);
    } else if (outcome === "preventedLikely") {
        preventedLikely++;
        inc(categoryPrevented, cat, 1);
        if (examples.preventedLikely.length < 5) examples.preventedLikely.push(payload);
    } else {
        unknownNoSignal++;
        inc(categoryUnknown, cat, 1);
        if (examples.unknownNoSignal.length < 5) examples.unknownNoSignal.push(payload);
    }
}

// --- output ---
console.log("=== CSP XSS Evaluation Summary ===");
console.log("Input:", input);
console.log("Records:", total, "(parse errors:", parseErrors + ")");
console.log("");

console.log("XSS fired (hook fired):", fired, `(${pct(fired, total)})`);
console.log("Prevented likely (NOT fired + CSP violation/report observed):", preventedLikely, `(${pct(preventedLikely, total)})`);
console.log("Unknown (NOT fired + no CSP signal):", unknownNoSignal, `(${pct(unknownNoSignal, total)})`);
console.log("");

console.log("Estimated 'prevent rate' (preventedLikely / total):", pct(preventedLikely, total));
console.log("Estimated 'success rate' (fired / total):         ", pct(fired, total));

if (strictMode) {
    const evaluable = total - unknownNoSignal;
    console.log("");
    console.log("Strict rates (excluding Unknown as 'not evaluable'):");
    console.log("  evaluable:", evaluable);
    console.log("  prevent rate (preventedLikely / evaluable):", pct(preventedLikely, evaluable));
    console.log("  success rate (fired / evaluable):          ", pct(fired, evaluable));
}

console.log("");

console.log(`--- Top CSP effectiveDirective (top ${topN}) ---`);
for (const [k, v] of topEntries(directiveCounts, topN)) {
    console.log(String(v).padStart(6), k);
}
console.log("");

console.log(`--- Top CSP violatedDirective (top ${topN}) ---`);
for (const [k, v] of topEntries(violatedDirectiveCounts, topN)) {
    console.log(String(v).padStart(6), k);
}
console.log("");

console.log(`--- Top CSP blockedURI (top ${topN}) ---`);
for (const [k, v] of topEntries(blockedUriCounts, topN)) {
    console.log(String(v).padStart(6), k);
}
console.log("");

console.log(`--- Category breakdown ---`);
const cats = [...categoryTotals.keys()].sort((a, b) => (categoryTotals.get(b) - categoryTotals.get(a)));
for (const c of cats) {
    const t = categoryTotals.get(c) || 0;
    const f = categoryFired.get(c) || 0;
    const p = categoryPrevented.get(c) || 0;
    const u = categoryUnknown.get(c) || 0;

    console.log(
        c.padEnd(18),
        "total", String(t).padStart(6),
        " fired", String(f).padStart(6), pct(f, t).padStart(8),
        " prevented", String(p).padStart(6), pct(p, t).padStart(8),
        " unknown", String(u).padStart(6), pct(u, t).padStart(8),
    );
}
console.log("");

console.log("--- Example payloads (up to 5 each) ---");
console.log("[Fired]");
examples.fired.forEach((p, i) => console.log(` ${i + 1}. ${p}`));
console.log("[Prevented likely]");
examples.preventedLikely.forEach((p, i) => console.log(` ${i + 1}. ${p}`));
console.log("[Unknown]");
examples.unknownNoSignal.forEach((p, i) => console.log(` ${i + 1}. ${p}`));

// --- CSV export (optional) ---
if (csvPath) {
    const header = [
        "category,total,fired,fired_rate,prevented_likely,prevented_rate,unknown,unknown_rate"
    ].join(",");

    const rows = [header];
    for (const c of cats) {
        const t = categoryTotals.get(c) || 0;
        const f = categoryFired.get(c) || 0;
        const p = categoryPrevented.get(c) || 0;
        const u = categoryUnknown.get(c) || 0;

        rows.push([
            JSON.stringify(c),
            t,
            f,
            (t ? (f / t) : 0).toFixed(6),
            p,
            (t ? (p / t) : 0).toFixed(6),
            u,
            (t ? (u / t) : 0).toFixed(6),
        ].join(","));
    }

    fs.writeFileSync(csvPath, rows.join("\n") + "\n", "utf8");
    console.log("");
    console.log("Wrote CSV:", csvPath);
}

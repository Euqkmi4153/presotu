// run_payload_tests.mjs (resume-capable)
// Usage:
//   node run_payload_tests.mjs ./payloads.txt ./results.jsonl --baseline
//   node run_payload_tests.mjs ./payloads.txt ./results.jsonl --enforce
//   node run_payload_tests.mjs ./payloads.txt ./results.jsonl --no-resume   # 再開なし（毎回最初から）
//
// Resume behavior (default ON):
// - If outputFile already exists, read it and build a set of already-tested payload strings.
// - When running again, skip payloads that already exist in output results.
// - This prevents duplicates even if a previous run stopped halfway.

import fs from "fs";
import readline from "readline";
import { chromium } from "playwright";

const payloadFile = process.argv[2];
const outputFile = process.argv[3];

if (!payloadFile || !outputFile) {
    console.error("Usage: node run_payload_tests.mjs <payloads.txt> <results.jsonl> [--baseline|--enforce] [--no-resume]");
    process.exit(1);
}

const isBaseline = process.argv.includes("--baseline");
const isEnforce = process.argv.includes("--enforce");
const resumeEnabled = !process.argv.includes("--no-resume");

// あなたの運用に合わせて切替してOK（今は同じURL）
const TARGET_URL = "http://localhost:8080/_local_test1";
const TIMEOUT_MS = 3000;

function nowISO() {
    return new Date().toISOString();
}
function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
}

async function loadAlreadyTestedPayloads(resultsPath) {
    const tested = new Set();
    let maxIndex = 0;
    let records = 0;
    let parseErrors = 0;

    if (!fs.existsSync(resultsPath)) {
        return { tested, maxIndex, records, parseErrors };
    }

    const rl = readline.createInterface({
        input: fs.createReadStream(resultsPath, "utf8"),
        crlfDelay: Infinity,
    });

    for await (const line of rl) {
        const s = line.trim();
        if (!s) continue;
        try {
            const rec = JSON.parse(s);
            if (rec && typeof rec.payload === "string") tested.add(rec.payload);
            if (typeof rec.index === "number" && rec.index > maxIndex) maxIndex = rec.index;
            records++;
        } catch {
            parseErrors++;
        }
    }

    return { tested, maxIndex, records, parseErrors };
}

(async () => {
    // --- resume preload ---
    let already = { tested: new Set(), maxIndex: 0, records: 0, parseErrors: 0 };
    if (resumeEnabled) {
        already = await loadAlreadyTestedPayloads(outputFile);
        console.log(
            `[RESUME] enabled. existing records=${already.records}, parseErrors=${already.parseErrors}, uniquePayloads=${already.tested.size}`
        );
    } else {
        console.log("[RESUME] disabled (--no-resume). will run from the beginning and append results.");
    }

    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    const out = fs.createWriteStream(outputFile, { flags: "a" });

    // payloadごとの「現在の結果」
    let currentResult = null;

    // exposeFunction は必ず1回だけ
    await page.exposeFunction("__xss_hook__", (msg) => {
        if (!currentResult) return;
        currentResult.fired = true;
        currentResult.firedLogs.push(String(msg));
    });

    // payload reader
    const rl = readline.createInterface({
        input: fs.createReadStream(payloadFile, "utf8"),
        crlfDelay: Infinity,
    });

    let index = already.maxIndex; // ★続き番号（見た目用）を継続したいならこれが便利
    let seenPayloadLines = 0;
    let skipped = 0;
    let executed = 0;

    for await (const line of rl) {
        const payload = line.trim();
        if (!payload || payload.startsWith("#")) continue;

        seenPayloadLines++;

        // ★再開：すでに試したpayloadはスキップ（重複追記を防ぐ）
        if (resumeEnabled && already.tested.has(payload)) {
            skipped++;
            continue;
        }

        index++;

        const result = {
            index,
            mode: isEnforce ? "enforce" : (isBaseline ? "baseline" : "default"),
            payload,
            url: TARGET_URL,
            fired: false,
            firedLogs: [],
            cspViolations: [],
            timestamp: nowISO(),
        };

        currentResult = result;

        // console handler の async を確実に待つための Promise 群
        const pending = [];

        const onConsole = (msg) => {
            const text = msg.text();

            if (text.includes("[CSP-violation]") || text.includes("[CSP_VIOLATION]")) {
                const p = (async () => {
                    try {
                        const args = msg.args();
                        if (args.length >= 2) {
                            const obj = await args[1].jsonValue().catch(() => null);
                            if (obj && typeof obj === "object") {
                                result.cspViolations.push(obj);
                                return;
                            }
                        }
                        result.cspViolations.push({ raw: text });
                    } catch (e) {
                        result.cspViolations.push({ raw: text, parseError: String(e?.message || e) });
                    }
                })();
                pending.push(p);
            }
        };

        page.on("console", onConsole);

        try {
            await page.goto("about:blank");
            await page.goto(TARGET_URL, { waitUntil: "load" });

            await page.evaluate((payload) => {
                const container = document.createElement("div");
                container.id = "__payload_container__";
                container.innerHTML = payload;
                document.body.appendChild(container);
            }, payload);

            await sleep(TIMEOUT_MS);

            if (pending.length) {
                await Promise.allSettled(pending);
            }
        } catch (e) {
            result.error = String(e && e.message ? e.message : e);
        } finally {
            page.off("console", onConsole);
            currentResult = null;
        }

        out.write(JSON.stringify(result) + "\n");

        // ★再開用Setにも追加しておく（同一実行内の重複も防ぐ）
        if (resumeEnabled) already.tested.add(payload);

        executed++;
        if ((executed + skipped) % 50 === 0) {
            console.log(`[INFO] scanned=${executed + skipped} executed=${executed} skipped=${skipped}`);
        }
    }

    await browser.close();
    out.end();

    console.log("[DONE] results written to", outputFile);
    console.log(`[DONE] scannedPayloadLines=${seenPayloadLines} executed=${executed} skipped(existing)=${skipped}`);
})();

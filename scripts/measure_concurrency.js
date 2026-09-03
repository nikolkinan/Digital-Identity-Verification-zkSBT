// scripts/measure_concurrency.js
//
// Concurrency benchmark proof generation (client-side).
// Measuring proving throughput at different concurrency levels demonstrates the acceleration gained from parallelism and the point of saturation.
//
// Approach: Separate process (child_process), not worker thread.
// snarkjs uses an internal web worker that conflicts when wrapped in a worker thread (nested workers). Each proof is executed as a clean Node process via prove_one.js, providing true CPU concurrency and memory isolation without web worker conflicts.
//
// Concurrency = the number of proving processes running simultaneously. We execute a total of TOTAL_PROOFS proofs using a pool of size W (with a maximum of W processes running at once). Measure the total wall-clock time and calculate the throughput (proofs/second). Repeat for W = 1, 2, 4, 8.
//
// node scripts/measure_concurrency.js

const { spawn } = require("node:child_process");
const os = require("os");
const fs = require("fs");
const path = require("path");

const TOTAL_PROOFS = 32;
const CONCURRENCY_LEVELS = [1, 2, 4, 8];
const PROVE_ONE = path.join(__dirname, "prove_one.js");

// Run a single proving process, resolve with the proving time (ms) from stdout.
function proveInProcess(seed) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [PROVE_ONE, String(seed)], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => { out += d.toString(); });
    child.stderr.on("data", (d) => { err += d.toString(); });
    child.on("close", (code) => {
      if (code !== 0) return reject(new Error("prove_one exit " + code + ": " + err.slice(0, 200)));

      const lines = out.trim().split("\n").filter(Boolean);
      for (let i = lines.length - 1; i >= 0; i--) {
        try { const o = JSON.parse(lines[i]); if (typeof o.ms === "number") return resolve(o.ms); } catch {}
      }
      reject(new Error("No valid ms output.: " + out.slice(0, 200)));
    });
  });
}

// Run  total tasks with a maximum of w processes running concurrently.
async function runPool(total, w) {
  const times = [];
  let next = 0;
  async function worker() {
    while (true) {
      const seed = next++;
      if (seed >= total) break;
      times.push(await proveInProcess(seed));
    }
  }
  await Promise.all(Array.from({ length: w }, () => worker()));
  return times;
}

async function measureLevel(w) {
  const t0 = Date.now();
  const times = await runPool(TOTAL_PROOFS, w);
  const wall = Date.now() - t0;
  const throughput = (TOTAL_PROOFS / wall) * 1000;
  const meanProof = times.reduce((a, b) => a + b, 0) / times.length;
  return { workers: w, wallMs: wall, throughput, meanProofMs: meanProof, count: times.length };
}

async function main() {
  console.log("=".repeat(60));
  console.log("zkSBT — Proof Generation Concurrency Benchmark");
  console.log("=".repeat(60));
  console.log("CPU:", os.cpus()[0].model);
  console.log("Logical Cores:", os.cpus().length);
  console.log("Total proof per level:", TOTAL_PROOFS);
  console.log("Concurrency levels:", CONCURRENCY_LEVELS.join(", "), "parallel processes");
  console.log("Method: Separate processes (avoid web-worker conflicts in snarkjs)\n");

  const rows = [];
  let baseline = null;
  for (const w of CONCURRENCY_LEVELS) {
    process.stdout.write(`[${w} parallel] running ${TOTAL_PROOFS} proof... `);
    const r = await measureLevel(w);
    if (w === 1) baseline = r.throughput;
    r.speedup = r.throughput / baseline;
    rows.push(r);
    console.log(`done. ${(r.wallMs/1000).toFixed(1)} s, ${r.throughput.toFixed(2)} proof/s, speedup ${r.speedup.toFixed(2)}x`);
  }

  const outDir = path.join(__dirname, "..", "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const csv = ["parallelism,wallMs,throughputPerSec,meanProofMs,speedup"];
  for (const r of rows) csv.push(`${r.workers},${r.wallMs},${r.throughput.toFixed(3)},${r.meanProofMs.toFixed(1)},${r.speedup.toFixed(3)}`);
  fs.writeFileSync(path.join(outDir, "concurrency.csv"), csv.join("\n"));
  fs.writeFileSync(path.join(outDir, "concurrency.json"), JSON.stringify({
    cpu: os.cpus()[0].model, cores: os.cpus().length, totalProofs: TOTAL_PROOFS, rows,
  }, null, 2));
  console.log("\nWritten: results/concurrency.csv, results/concurrency.json");

  console.log("\n" + "=".repeat(60));
  console.log("Summary");
  console.log("=".repeat(60));
  console.log("Parallel | Throughput (proof/s) | Speedup | Mean proof (ms)");
  for (const r of rows) {
    console.log(`  ${String(r.workers).padStart(2)}     |  ${r.throughput.toFixed(2).padStart(8)}          |  ${r.speedup.toFixed(2)}x   |  ${r.meanProofMs.toFixed(0)}`);
  }
  const best = rows.reduce((a, b) => b.throughput > a.throughput ? b : a);
  console.log(`\nPeak throughput: ${best.throughput.toFixed(2)} proof/s di ${best.workers} parallel processes (${best.speedup.toFixed(2)}x sequential).`);
  console.log("Note: mean proof (ms) per-proof increases with high concurrency because cores share the workload;");
  console.log("what matters is the aggregate throughput, not the latency per-proof.");
  process.exit(0);
}
main().catch((e) => { console.error("\n[FATAL]", e.message || e); process.exit(1); });
import { readFile } from "node:fs/promises";
import { analyze } from "./oracle.ts";
import { parseJsonl } from "./parser.ts";

const args = process.argv.slice(2);
const path = args.find((a) => !a.startsWith("--"));
if (!path || args.includes("--help")) {
  console.log("Usage: node --experimental-strip-types src/cli.ts TRACE.jsonl [--json] [--strict]");
  if (!path) process.exitCode = args.includes("--help") ? 0 : 1;
} else {
  try {
    const content = await readFile(path, "utf8");
    if (Buffer.byteLength(content, "utf8") > 10_000_000)
      throw new Error("Input exceeds 10 MB offline safety limit");
    const events = parseJsonl(content);
    if (events.length > 50_000) throw new Error("Input exceeds 50,000 event limit");
    const findings = analyze(events);
    const output = { trace: path, events: events.length, findings: findings.length, results: findings };
    if (args.includes("--json")) console.log(JSON.stringify(output, null, 2));
    else {
      console.log("PairTrace offline check: " + events.length + " synthetic/normalized events, " + findings.length + " finding(s)");
      for (const f of findings) console.log("[" + f.severity + "] event " + f.index + " " + f.rule + ": " + f.message);
    }
    if (args.includes("--strict") && findings.some((f) => f.severity === "policy_violation"))
      process.exitCode = 2;
  } catch (error) {
    console.error("PairTrace: " + (error instanceof Error ? error.message : String(error)));
    process.exitCode = 1;
  }
}

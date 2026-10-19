import { readFile } from "node:fs/promises";
import { analyzeOpenClawWire, parseOpenClawCapture } from "./adapters/openclaw.ts";

const args = process.argv.slice(2);
if (args.includes("--help")) {
  console.log("Usage: node --experimental-strip-types src/cli-gateway.ts TRACE.jsonl [--json]");
} else {
  const paths = args.filter((arg) => !arg.startsWith("--"));
  if (paths.length !== 1 || args.some((arg) => arg.startsWith("--") && arg !== "--json")) {
    console.error("Usage: node --experimental-strip-types src/cli-gateway.ts TRACE.jsonl [--json]");
    process.exitCode = 1;
  } else {
    try {
      const bytes = await readFile(paths[0]!);
      if (bytes.length > 10_000_000) throw new Error("Input exceeds 10 MB");
      const capture = parseOpenClawCapture(bytes.toString("utf8"));
      const report = analyzeOpenClawWire(capture);
      if (args.includes("--json")) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log("PairTrace OpenClaw WS observer: " + report.schema);
        console.log(report.frames + " frames, " + report.observations.length + " classified observations, " + report.review.length + " review item(s)");
        for (const o of report.observations) console.log(o.connection + " #" + o.index + " " + o.kind + (o.status ? " (" + o.status + ")" : ""));
        for (const r of report.review) console.log("REVIEW " + r.connection + " #" + r.index + " " + r.code);
        console.log("No vendor vulnerability is inferred from this report.");
      }
    } catch (e) {
      // Never print snippets from raw captured data in error messages.
      console.error("Invalid or unreadable capture: " + (e instanceof Error ? e.message : "unknown"));
      process.exitCode = 1;
    }
  }
}

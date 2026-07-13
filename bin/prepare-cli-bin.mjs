import { readFileSync, writeFileSync, chmodSync, statSync } from "node:fs";

const shebang = "#!/usr/bin/env node\n";
const targets = ["lib/cjs/bin/cli.cjs", "lib/esm/bin/cli.js"];

for (const target of targets) {
  const content = readFileSync(target, "utf8");
  const nextContent = content.startsWith(shebang) ? content : shebang + content;

  if (nextContent !== content) {
    writeFileSync(target, nextContent);
  }

  const mode = statSync(target).mode | 0o755;
  chmodSync(target, mode);
}

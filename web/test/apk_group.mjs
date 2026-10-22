import { readApk } from "../build/apk.node.mjs";
import fs from "fs";
const dir = "/home/claude/samples/ag/tests/data/APK/apksig/";
const g = {};
for (const f of fs.readdirSync(dir).filter(f=>/^v[23]-only-with-/.test(f) && !/does-not-verify|missing|empty|unknown|wrong|mismatch|corrupt/.test(f))) {
  const b = fs.readFileSync(dir + f);
  try { const r = await readApk(b.buffer.slice(b.byteOffset, b.byteOffset + b.length));
    (g[r.digest] ||= []).push(f + " cert=" + r.certHash.slice(2,10)); } catch(e){}
}
for (const [d, fs2] of Object.entries(g)) { console.log(d.slice(0,18), fs2.length, "files,", new Set(fs2.map(x=>x.split("cert=")[1])).size, "distinct certs"); }

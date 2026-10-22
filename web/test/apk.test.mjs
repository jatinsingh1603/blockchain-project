import { readApk } from "../build/apk.node.mjs";
import fs from "fs";
const dir = "/home/claude/samples/ag/tests/data/APK/";
const files = ["hello-world.apk","TestActivity_signed_both.apk","a2dp.Vol_137.apk","apksig/v3-only-with-rsa-pkcs1-sha256-2048.apk","apksig/v2-only-with-rsa-pkcs1-sha256-16384.apk","apksig/golden-legacy-aligned-v1v2v3-lineage-out.apk","app-prod-debug.apk"];
for (const f of files) {
  const b = fs.readFileSync(dir + f);
  try {
    const r = await readApk(b.buffer.slice(b.byteOffset, b.byteOffset + b.length));
    console.log(f, JSON.stringify({p:r.packageName,v:r.versionCode,s:r.schemes,c:r.certHash?.slice(0,14),d:r.digest.slice(0,14)}));
  } catch (e) { console.log(f, "ERR", e.message); }
}

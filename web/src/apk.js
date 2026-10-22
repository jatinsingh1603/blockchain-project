// Reads a real APK in the browser.
// 1. Signing-independent content digest D (same rule as the paper, Section 4.2)
// 2. Signing certificate hash C from the APK Signature Scheme v3 or v2 block
// 3. Package name and versionCode from the binary AndroidManifest.xml

const EOCD_SIG = 0x06054b50;
const MAGIC = "APK Sig Block 42";
const V2_ID = 0x7109871a;
const V3_ID = 0xf05368c0;

const te = new TextDecoder("latin1");

async function sha256(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return "0x" + [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function findEOCD(dv) {
  const min = Math.max(0, dv.byteLength - 65557);
  for (let i = dv.byteLength - 22; i >= min; i--) {
    if (dv.getUint32(i, true) === EOCD_SIG) return i;
  }
  throw new Error("Not a ZIP/APK file (end of central directory not found)");
}

function locate(buf) {
  const dv = new DataView(buf);
  const eocd = findEOCD(dv);
  const cdOffset = dv.getUint32(eocd + 16, true);
  const cdSize = dv.getUint32(eocd + 12, true);
  const entries = dv.getUint16(eocd + 10, true);
  let sigStart = cdOffset, sigBlock = null;
  if (cdOffset >= 24 && te.decode(new Uint8Array(buf, cdOffset - 16, 16)) === MAGIC) {
    const size = Number(dv.getBigUint64(cdOffset - 24, true));
    sigStart = cdOffset - (size + 8);
    sigBlock = { start: sigStart, pairsStart: sigStart + 8, pairsEnd: cdOffset - 24 };
  }
  return { dv, eocd, cdOffset, cdSize, entries, sigStart, sigBlock };
}

export async function contentDigest(buf, loc = locate(buf)) {
  const p1 = new Uint8Array(buf, 0, loc.sigStart);
  const p3 = new Uint8Array(buf, loc.cdOffset, loc.eocd - loc.cdOffset);
  const p4 = new Uint8Array(buf.slice(loc.eocd));
  new DataView(p4.buffer).setUint32(16, loc.sigStart, true);
  const all = new Uint8Array(p1.length + p3.length + p4.length);
  all.set(p1, 0); all.set(p3, p1.length); all.set(p4, p1.length + p3.length);
  return sha256(all);
}

// length-prefixed (uint32) sequence reader
function lpSeq(dv, start, end) {
  const items = [];
  let p = start;
  while (p + 4 <= end) {
    const len = dv.getUint32(p, true);
    items.push({ start: p + 4, end: p + 4 + len });
    p += 4 + len;
  }
  return items;
}

function firstCertFromSchemeBlock(dv, start, end, isV3) {
  // block: length-prefixed sequence of length-prefixed signers
  const signersSeq = lpSeq(dv, start, end)[0];
  const signer = lpSeq(dv, signersSeq.start, signersSeq.end)[0];
  // signer: length-prefixed signed data, ...
  const signedData = { start: signer.start + 4, end: signer.start + 4 + dv.getUint32(signer.start, true) };
  // signed data: digests (lp), certificates (lp), ...
  let p = signedData.start;
  const digestsLen = dv.getUint32(p, true);
  p += 4 + digestsLen;
  const certsLen = dv.getUint32(p, true);
  const certs = lpSeq(dv, p + 4, p + 4 + certsLen);
  if (!certs.length) throw new Error("No certificate in signing block");
  return { start: certs[0].start, end: certs[0].end, scheme: isV3 ? "v3" : "v2" };
}

export async function signingInfo(buf, loc = locate(buf)) {
  const schemes = [];
  let cert = null;
  if (loc.sigBlock) {
    const dv = loc.dv;
    let p = loc.sigBlock.pairsStart;
    const pairs = {};
    while (p + 12 <= loc.sigBlock.pairsEnd) {
      const len = Number(dv.getBigUint64(p, true));
      const id = dv.getUint32(p + 8, true);
      pairs[id] = { start: p + 12, end: p + 8 + len };
      p += 8 + len;
    }
    if (pairs[V2_ID]) schemes.push("v2");
    if (pairs[V3_ID]) schemes.push("v3");
    const use = pairs[V3_ID] ? [pairs[V3_ID], true] : pairs[V2_ID] ? [pairs[V2_ID], false] : null;
    if (use) cert = firstCertFromSchemeBlock(dv, use[0].start, use[0].end, use[1]);
  }
  const certHash = cert ? await sha256(new Uint8Array(buf, cert.start, cert.end - cert.start)) : null;
  return { schemes, certHash, certScheme: cert?.scheme || null };
}

// ---- ZIP entry reading ----
function listEntries(buf, loc) {
  const dv = loc.dv;
  const out = {};
  let p = loc.cdOffset;
  for (let i = 0; i < loc.entries && p < loc.eocd; i++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    const csize = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const local = dv.getUint32(p + 42, true);
    const name = te.decode(new Uint8Array(buf, p + 46, nameLen));
    out[name] = { method, csize, local };
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

async function inflateRaw(bytes) {
  const ds = new DecompressionStream("deflate-raw");
  const stream = new Blob([bytes]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function readEntry(buf, loc, e) {
  const dv = loc.dv;
  const nameLen = dv.getUint16(e.local + 26, true);
  const extraLen = dv.getUint16(e.local + 28, true);
  const data = new Uint8Array(buf, e.local + 30 + nameLen + extraLen, e.csize);
  if (e.method === 0) return data;
  if (e.method === 8) return inflateRaw(data);
  throw new Error("Unsupported compression method " + e.method);
}

// ---- Binary XML (AXML) manifest parsing ----
function parseAxml(u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  let strings = [];
  let p = dv.getUint16(2, true); // file header size
  while (p + 8 <= dv.byteLength) {
    const type = dv.getUint16(p, true);
    const headerSize = dv.getUint16(p + 2, true);
    const size = dv.getUint32(p + 4, true);
    if (size === 0) break;
    if (type === 0x0001) {
      const count = dv.getUint32(p + 8, true);
      const flags = dv.getUint32(p + 16, true);
      const strStart = dv.getUint32(p + 20, true);
      const utf8 = (flags & 0x100) !== 0;
      for (let i = 0; i < count; i++) {
        const off = p + strStart + dv.getUint32(p + headerSize + i * 4, true);
        if (utf8) {
          let q = off;
          q += (u8[q] & 0x80) ? 2 : 1; // utf16 length
          let n = u8[q];
          if (n & 0x80) { n = ((n & 0x7f) << 8) | u8[q + 1]; q += 2; } else q += 1;
          strings.push(new TextDecoder("utf-8").decode(u8.subarray(q, q + n)));
        } else {
          let n = dv.getUint16(off, true), q = off + 2;
          if (n & 0x8000) { n = ((n & 0x7fff) << 16) | dv.getUint16(off + 2, true); q += 2; }
          strings.push(new TextDecoder("utf-16le").decode(u8.subarray(q, q + n * 2)));
        }
      }
    } else if (type === 0x0102) {
      const name = strings[dv.getUint32(p + 20, true)];
      if (name === "manifest") {
        const attrStart = dv.getUint16(p + 24, true);
        const attrSize = dv.getUint16(p + 26, true);
        const count = dv.getUint16(p + 28, true);
        const res = {};
        for (let i = 0; i < count; i++) {
          const a = p + 16 + attrStart + i * attrSize;
          const an = strings[dv.getUint32(a + 4, true)];
          const raw = dv.getUint32(a + 8, true);
          const dataType = dv.getUint8(a + 15);
          const data = dv.getUint32(a + 16, true);
          res[an] = dataType === 0x03 ? strings[data] : (raw !== 0xffffffff ? strings[raw] : data);
        }
        return res;
      }
    }
    p += size;
  }
  return {};
}

export async function readApk(file) {
  const buf = file instanceof ArrayBuffer ? file : await file.arrayBuffer();
  const loc = locate(buf);
  const entries = listEntries(buf, loc);
  let manifest = {};
  if (entries["AndroidManifest.xml"]) {
    try { manifest = parseAxml(await readEntry(buf, loc, entries["AndroidManifest.xml"])); } catch (e) { manifest = {}; }
  }
  const hasV1 = Object.keys(entries).some((n) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(n));
  const sig = await signingInfo(buf, loc);
  const digest = await contentDigest(buf, loc);
  return {
    size: buf.byteLength,
    entryCount: Object.keys(entries).length,
    packageName: manifest.package || null,
    versionCode: manifest.versionCode != null ? Number(manifest.versionCode) : null,
    versionName: manifest.versionName || null,
    schemes: (hasV1 ? ["v1"] : []).concat(sig.schemes),
    certHash: sig.certHash,
    certScheme: sig.certScheme,
    digest,
    hasSigBlock: !!loc.sigBlock,
  };
}

// Simulate an attacker injecting code: flip bytes inside the first ZIP entry's data.
export function injectCode(buf) {
  const copy = buf.slice(0);
  const dv = new DataView(copy);
  const nameLen = dv.getUint16(26, true), extraLen = dv.getUint16(28, true);
  const pos = 30 + nameLen + extraLen + 8;
  const u8 = new Uint8Array(copy);
  for (let i = 0; i < 4; i++) u8[pos + i] ^= 0xff;
  return copy;
}

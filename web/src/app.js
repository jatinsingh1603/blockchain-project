import { LocalChain, STATUS, appIdOf } from "./chain.js";
import { readApk, injectCode } from "./apk.js";
import { keccak256, toUtf8Bytes, ZeroHash } from "ethers";

const $ = (id) => document.getElementById(id);
const ATTACKER_CERT = keccak256(toUtf8Bytes("attacker-certificate"));
const REASONS = {
  OK: "All five checks passed.",
  UNKNOWN_APP: "This package is not registered on the chain.",
  SIGNER_MISMATCH: "The APK is signed by a different certificate.",
  REVOKED: "The developer revoked this release.",
  BELOW_VERSION_FLOOR: "This version is older than the allowed minimum.",
  QUORUM_NOT_REACHED: "Fewer than k builders vote for this exact build.",
};

let chain, apk = null, registered = false, busy = false;
const voted = new Set();

async function boot() {
  chain = await new LocalChain().init(["Developer", "B1", "B2", "B3", "Attacker"]);
  await chain.deploy();
  registered = false; voted.clear();
  renderChain(); renderLedger(); refreshButtons();
}

function renderChain() {
  $("chainStatus").innerHTML = `Local chain running, block <b>${chain.blockNumber}</b><br>Contract <code>${chain.contractHex.slice(0, 10)}...${chain.contractHex.slice(-6)}</code>`;
}
function renderLedger() {
  $("ledger").innerHTML = chain.ledger.map((e) => `<tr>
    <td class="num">#${e.block}</td><td>${e.from}</td><td>${e.label}</td><td class="num">${e.gas.toLocaleString()}</td>
    <td>${e.status === "success" ? '<span class="ok">Success</span>' : `<span class="bad">Reverted: ${e.reason}</span>`}</td></tr>`).join("");
  renderChain();
}

function refreshButtons() {
  const has = !!apk;
  $("regBtn").disabled = !has || registered;
  $("regBtn").classList.toggle("done", registered);
  $("regBtn").textContent = registered ? "Registered" : "Register";
  document.querySelectorAll(".voteBtn").forEach((b) => {
    const done = voted.has(b.dataset.b);
    b.disabled = !has || !registered || done;
    b.classList.toggle("done", done);
  });
  $("verify2").disabled = !has;
  document.querySelectorAll(".atk").forEach((b) => (b.disabled = !has));
}

async function loadBuffer(buf, name) {
  try {
    const info = await readApk(buf);
    if (!info.packageName || info.versionCode == null) throw new Error("Could not read the package name or version from AndroidManifest.xml");
    apk = { buf, info, name };
    $("fPkg").textContent = info.packageName;
    $("fVer").textContent = info.versionCode + (info.versionName ? ` (${info.versionName})` : "");
    $("fSch").textContent = info.schemes.join(", ") || "none";
    $("fSize").textContent = (info.size / 1024).toFixed(0) + " KB";
    $("fD").textContent = info.digest;
    $("fC").textContent = info.certHash || "No v2/v3 signing block found";
    const notes = [];
    if (!info.certHash) notes.push("This APK has only v1 signing, so the digest depends on the signer. The design expects v2 or later.");
    else if (info.schemes.includes("v1")) notes.push("This APK also has a v1 signature, which sits inside the ZIP entries. Builders must use the same v1 files to agree.");
    $("fNoteRow").hidden = !notes.length; $("fNote").textContent = notes.join(" ");
    $("facts").hidden = false; $("checks").hidden = false; $("verifyBtn").hidden = false;
    resetChecks(); $("verdict").hidden = true;
    registered = await isRegistered(); voted.clear();
    refreshButtons();
  } catch (e) {
    showVerdict(false, "Could not read this file", e.message);
  }
}

async function isRegistered() {
  const a = await chain.view("apps", [appIdOf(apk.info.packageName)]);
  return a.exists;
}

function resetChecks() { document.querySelectorAll("#checks li").forEach((li) => (li.className = "")); }
function showVerdict(ok, title, sub) {
  const v = $("verdict");
  v.hidden = false; v.className = "verdict " + (ok ? "ok" : "bad");
  v.innerHTML = `${title}<small>${sub}</small>`;
}

async function verify(digest, cert, label) {
  const { packageName, versionCode } = apk.info;
  const s = STATUS[Number((await chain.view("verify", [appIdOf(packageName), versionCode, digest, cert || ZeroHash]))[0])];
  resetChecks();
  const failAt = s === "OK" ? 6 : STATUS.indexOf(s);
  const items = [...document.querySelectorAll("#checks li")];
  for (let i = 0; i < items.length; i++) {
    await new Promise((r) => setTimeout(r, 140));
    if (i + 1 < failAt) items[i].className = "pass";
    else if (i + 1 === failAt) { items[i].className = "fail"; break; }
  }
  showVerdict(s === "OK", (s === "OK" ? "Install allowed" : "Install blocked") + (label ? `: ${label}` : ""), `${s}. ${REASONS[s]}`);
  return s;
}

async function guarded(fn) {
  if (busy) return; busy = true;
  try { await fn(); } catch (e) { showVerdict(false, "Something went wrong", e.message); }
  busy = false; renderLedger(); refreshButtons();
}

async function register() {
  const { packageName, certHash } = apk.info;
  const builders = ["B1", "B2", "B3"].map((n) => chain.accounts[n].hex);
  const e = await chain.call("Developer", "registerApp", [packageName, builders, 2, certHash || ZeroHash], `registerApp ${packageName}`);
  registered = e.status === "success";
}
async function vote(b, digest = apk.info.digest, label) {
  const e = await chain.call(b, "attest", [appIdOf(apk.info.packageName), apk.info.versionCode, digest], label || `attest v${apk.info.versionCode}`);
  if (e.status === "success") voted.add(b);
  return e;
}
async function ensureRelease() {
  if (!registered) await register();
  for (const b of ["B1", "B2"]) if (!voted.has(b)) await vote(b);
}

const attacks = {
  async build() {
    await ensureRelease();
    const bad = await readApk(injectCode(apk.buf));
    if (!voted.has("B3")) await vote("B3", bad.digest, `attest v${apk.info.versionCode} (backdoored build)`);
    return verify(bad.digest, apk.info.certHash, "backdoored build");
  },
  async key() {
    await ensureRelease();
    const bad = await readApk(injectCode(apk.buf));
    return verify(bad.digest, apk.info.certHash, "signed with stolen key");
  },
  async repack() {
    await ensureRelease();
    const bad = await readApk(injectCode(apk.buf));
    return verify(bad.digest, ATTACKER_CERT, "repackaged app");
  },
  async revoke() {
    await ensureRelease();
    await chain.call("Developer", "revoke", [appIdOf(apk.info.packageName), apk.info.versionCode], `revoke v${apk.info.versionCode}`);
    return verify(apk.info.digest, apk.info.certHash, "revoked release");
  },
  async floor() {
    await ensureRelease();
    await chain.call("Developer", "raiseVersionFloor", [appIdOf(apk.info.packageName), apk.info.versionCode + 1], `raise floor to v${apk.info.versionCode + 1}`);
    return verify(apk.info.digest, apk.info.certHash, "old version");
  },
  async outsider() {
    if (!registered) await register();
    const e = await chain.call("Attacker", "attest", [appIdOf(apk.info.packageName), apk.info.versionCode, apk.info.digest], "attest (outsider)");
    showVerdict(e.status !== "success", e.status === "success" ? "Vote accepted" : "Vote rejected by the contract", e.status === "success" ? "Unexpected." : `${e.reason}. Only registered builders can vote.`);
    return e.status === "success" ? "ACCEPTED" : e.reason;
  },
};

// Wiring
const drop = $("drop");
$("file").addEventListener("change", async (e) => { const f = e.target.files[0]; if (f) await loadBuffer(await f.arrayBuffer(), f.name); });
["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", async (e) => { const f = e.dataTransfer.files[0]; if (f) await loadBuffer(await f.arrayBuffer(), f.name); });
$("useDemo").addEventListener("click", async () => { const r = await fetch("samples/demo-app.apk"); await loadBuffer(await r.arrayBuffer(), "demo-app.apk"); });
$("regBtn").addEventListener("click", () => guarded(register));
document.querySelectorAll(".voteBtn").forEach((b) => b.addEventListener("click", () => guarded(() => vote(b.dataset.b))));
const doVerify = () => guarded(() => verify(apk.info.digest, apk.info.certHash));
$("verifyBtn").addEventListener("click", doVerify);
$("verify2").addEventListener("click", doVerify);
document.querySelectorAll(".atk").forEach((b) => b.addEventListener("click", () => guarded(async () => {
  const r = await attacks[b.dataset.a]();
  let res = b.parentElement.querySelector(".res");
  if (!res) { res = document.createElement("span"); b.previousElementSibling.appendChild(res); }
  const blocked = r !== "OK" && r !== "ACCEPTED";
  res.className = "res " + (blocked ? "ok" : "bad");
  res.textContent = blocked ? `Stopped: ${r}` : `Not stopped: ${r}`;
  $("gateTitle").scrollIntoView({ behavior: "smooth", block: "start" });
})));
$("resetBtn").addEventListener("click", () => guarded(async () => {
  await boot();
  document.querySelectorAll(".attacks .res").forEach((r) => r.remove());
  resetChecks(); $("verdict").hidden = true;
}));

// Phone-only: check an app that is already installed (Android app build only)
const Native = window.Capacitor?.isNativePlatform?.() ? window.Capacitor.Plugins.InstalledApps : null;
if (Native) {
  $("phoneBox").hidden = false;
  $("getApp").hidden = true;
  let apps = [];
  const render = () => {
    const q = $("appSearch").value.toLowerCase();
    $("appList").innerHTML = apps
      .filter((a) => !q || a.label.toLowerCase().includes(q) || a.packageName.includes(q))
      .map((a) => `<li><button data-p="${a.packageName}"><strong>${a.label.replace(/</g, "&lt;")}</strong><span>${a.packageName}, v${a.versionCode}, ${(a.size / 1048576).toFixed(1)} MB${a.split ? ", split app (base APK checked)" : ""}</span></button></li>`)
      .join("");
  };
  $("pickInstalled").addEventListener("click", async () => {
    $("pickInstalled").textContent = "Loading installed apps...";
    try {
      apps = (await Native.listApps()).apps.sort((a, b) => a.label.localeCompare(b.label));
      $("appSearch").hidden = false; render();
      $("pickInstalled").textContent = `${apps.length} apps found. Tap one to check it`;
    } catch (e) { $("pickInstalled").textContent = "Could not list apps: " + e.message; }
  });
  $("appSearch").addEventListener("input", render);
  $("appList").addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-p]");
    if (!b) return;
    b.querySelector("span").textContent = "Reading APK...";
    try {
      const { data } = await Native.readApk({ packageName: b.dataset.p });
      const bin = atob(data), u8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
      await loadBuffer(u8.buffer, b.dataset.p + ".apk");
      $("appList").innerHTML = ""; $("appSearch").hidden = true;
      $("pickInstalled").textContent = "Check another installed app";
      $("gateTitle").scrollIntoView({ behavior: "smooth" });
    } catch (err) { b.querySelector("span").textContent = "Could not read it: " + err.message; }
  });
}

boot().catch((e) => { $("chainStatus").textContent = "Chain failed to start: " + e.message; });

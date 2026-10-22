// Runs the attack scenarios and gas measurements on a local Hardhat chain.
// Output: results/gas.json and results/scenarios.json
const hre = require("hardhat");
const fs = require("fs");
const { ethers } = hre;

const STATUS = ["OK", "UNKNOWN_APP", "SIGNER_MISMATCH", "REVOKED", "BELOW_VERSION_FLOOR", "QUORUM_NOT_REACHED"];
const h = (s) => ethers.keccak256(ethers.toUtf8Bytes(s));

async function gasOf(txPromise) {
  const tx = await txPromise;
  const r = await tx.wait();
  return Number(r.gasUsed);
}

async function main() {
  const signers = await ethers.getSigners();
  const [dev, b1, b2, b3, attacker] = signers;
  const gas = {};

  const F = await ethers.getContractFactory("ReleaseRegistry");
  const reg = await F.deploy();
  const dr = await reg.deploymentTransaction().wait();
  gas.deploy = Number(dr.gasUsed);

  // Register apps with N = 3, 5, 7 builders to see how cost grows
  gas.registerApp = {};
  for (const n of [3, 5, 7]) {
    const builders = signers.slice(1, 1 + n).map((s) => s.address);
    const k = Math.floor(n / 2) + 1;
    gas.registerApp[n] = await gasOf(reg.connect(dev).registerApp(`com.demo.n${n}`, builders, k, h("cert")));
  }

  // Main demo app: 2-of-3
  const pkg = "com.example.wallet";
  const cert = h("developer-cert-v1");
  await (await reg.connect(dev).registerApp(pkg, [b1.address, b2.address, b3.address], 2, cert)).wait();
  const app = await reg.appIdOf(pkg);

  const goodV5 = h("clean-build-v5");
  const evilV5 = h("backdoored-build-v5");
  const goodV4 = h("clean-build-v4");
  const goodV3 = h("clean-build-v3");

  gas.attestFirst = await gasOf(reg.connect(b1).attest(app, 5, goodV5));
  gas.attestSecond = await gasOf(reg.connect(b2).attest(app, 5, goodV5));
  // Builder 3 is compromised and attests a different (malicious) digest
  gas.attestThird = await gasOf(reg.connect(b3).attest(app, 5, evilV5));

  for (const b of [b1, b2, b3]) await (await reg.connect(b).attest(app, 4, goodV4)).wait();
  for (const b of [b1, b2]) await (await reg.connect(b).attest(app, 3, goodV3)).wait();

  gas.revoke = await gasOf(reg.connect(dev).revoke(app, 4));
  gas.raiseFloor = await gasOf(reg.connect(dev).raiseVersionFloor(app, 4));

  const v = async (ver, dig, c) => STATUS[Number(await reg.verify(app, ver, dig, c))];
  gas.verifyEstimate = Number(await reg.verify.estimateGas(app, 5, goodV5, cert));

  const scenarios = [];
  const add = (id, name, expected, got) => scenarios.push({ id, name, expected, got, pass: expected === got });

  add("S1", "Clean release v5, 2 of 3 builders agree", "OK", await v(5, goodV5, cert));
  add("S2", "Build server compromise: backdoored v5 signed with real key, 1 of 3 builders", "QUORUM_NOT_REACHED", await v(5, evilV5, cert));
  add("S3", "Stolen signing key: attacker signs own build, no builder attested it", "QUORUM_NOT_REACHED", await v(5, h("attacker-build"), cert));
  add("S4", "Repackaged app: injected code, re-signed with attacker key", "SIGNER_MISMATCH", await v(5, h("repackaged"), h("attacker-cert")));
  add("S5", "Revoked release v4", "REVOKED", await v(4, goodV4, cert));
  add("S6", "Downgrade to old v3 below floor", "BELOW_VERSION_FLOOR", await v(3, goodV3, cert));
  add("S7", "Unknown package", "UNKNOWN_APP", STATUS[Number(await reg.verify(h("com.fake.app"), 1, goodV5, cert))]);

  // Access control checks: these must revert
  const mustRevert = async (p) => { try { await (await p).wait(); return false; } catch { return true; } };
  add("S8", "Non-builder tries to attest", "REVERT", (await mustRevert(reg.connect(attacker).attest(app, 6, evilV5))) ? "REVERT" : "ACCEPTED");
  add("S9", "Builder tries to vote twice for same version", "REVERT", (await mustRevert(reg.connect(b1).attest(app, 5, evilV5))) ? "REVERT" : "ACCEPTED");
  add("S10", "Non-owner tries to revoke a release", "REVERT", (await mustRevert(reg.connect(attacker).revoke(app, 5))) ? "REVERT" : "ACCEPTED");
  add("S11", "Owner tries to lower the version floor", "REVERT", (await mustRevert(reg.connect(dev).raiseVersionFloor(app, 1))) ? "REVERT" : "ACCEPTED");

  fs.mkdirSync("results", { recursive: true });
  fs.writeFileSync("results/gas.json", JSON.stringify(gas, null, 2));
  fs.writeFileSync("results/scenarios.json", JSON.stringify(scenarios, null, 2));
  console.log(JSON.stringify({ gas, scenarios }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });

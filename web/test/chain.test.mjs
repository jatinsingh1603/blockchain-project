// Node test: runs the same scenarios as the paper against the in-browser chain code.
import { LocalChain, STATUS, appIdOf } from "../build/chain.node.mjs";
import { keccak256, toUtf8Bytes } from "ethers";

const h = (s) => keccak256(toUtf8Bytes(s));
const c = await new LocalChain().init(["Developer", "B1", "B2", "B3", "Attacker"]);
const out = [];
out.push(["deploy", (await c.deploy()).gas]);
const pkg = "com.example.wallet", cert = h("developer-cert-v1");
out.push(["register", (await c.call("Developer", "registerApp", [pkg, ["B1", "B2", "B3"].map((n) => c.accounts[n].hex), 2, cert])).gas]);
const app = appIdOf(pkg);
const good = h("clean-build-v5"), evil = h("backdoored-build-v5");
out.push(["attest1", (await c.call("B1", "attest", [app, 5, good])).gas]);
out.push(["attest2", (await c.call("B2", "attest", [app, 5, good])).gas]);
out.push(["attest3-evil", (await c.call("B3", "attest", [app, 5, evil])).gas]);
const v = async (ver, d, ce) => STATUS[Number((await c.view("verify", [app, ver, d, ce]))[0])];
out.push(["S1", await v(5, good, cert)]);
out.push(["S2", await v(5, evil, cert)]);
out.push(["S4", await v(5, h("x"), h("attacker"))]);
const r = await c.call("Attacker", "attest", [app, 6, evil]);
out.push(["S8", r.status, r.reason]);
const r2 = await c.call("B1", "attest", [app, 5, evil]);
out.push(["S9", r2.status, r2.reason]);
console.log(JSON.stringify(out));

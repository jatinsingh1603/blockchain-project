// A small Ethereum chain that runs fully inside the browser.
// It executes the real compiled ReleaseRegistry bytecode with @ethereumjs/vm.
// Every transaction is signed with a throwaway key generated in the page and
// mined into its own simulated block. Nothing leaves the browser.
import { createVM, runTx } from "@ethereumjs/vm";
import { createLegacyTx } from "@ethereumjs/tx";
import { Common, Mainnet, Hardfork } from "@ethereumjs/common";
import { createBlock } from "@ethereumjs/block";
import { Account, Address, bytesToHex, hexToBytes, privateToAddress, randomBytes } from "@ethereumjs/util";
import { Interface, keccak256 as ekeccak, toUtf8Bytes } from "ethers";
import artifact from "./ReleaseRegistry.json";

export const iface = new Interface(artifact.abi);
export const STATUS = ["OK", "UNKNOWN_APP", "SIGNER_MISMATCH", "REVOKED", "BELOW_VERSION_FLOOR", "QUORUM_NOT_REACHED"];

export class LocalChain {
  async init(names) {
    this.common = new Common({ chain: Mainnet, hardfork: Hardfork.Cancun });
    this.vm = await createVM({ common: this.common });
    this.blockNumber = 0n;
    this.ledger = [];
    this.accounts = {};
    for (const name of names) {
      const pk = randomBytes(32);
      const address = new Address(privateToAddress(pk));
      await this.vm.stateManager.putAccount(address, new Account(0n, 10n ** 21n));
      this.accounts[name] = { name, pk, address, hex: address.toString(), nonce: 0n };
    }
    return this;
  }

  _block() {
    this.blockNumber += 1n;
    return createBlock(
      { header: { number: this.blockNumber, gasLimit: 30_000_000n, baseFeePerGas: 1n, timestamp: BigInt(Math.floor(Date.now() / 1000)) } },
      { common: this.common },
    );
  }

  async _send(from, to, data, label) {
    const acc = this.accounts[from];
    const tx = createLegacyTx(
      { nonce: acc.nonce, gasPrice: 1_000_000_000n, gasLimit: 3_000_000n, to: to ? to : undefined, data: hexToBytes(data) },
      { common: this.common },
    ).sign(acc.pk);
    const block = this._block();
    const res = await runTx(this.vm, { tx, block, skipBlockGasLimitValidation: true });
    acc.nonce += 1n;
    const failed = !!res.execResult.exceptionError;
    let reason = "";
    if (failed) {
      const ret = bytesToHex(res.execResult.returnValue);
      try { reason = iface.parseError(ret)?.name || "reverted"; } catch { reason = "reverted"; }
    }
    const entry = {
      block: Number(this.blockNumber),
      hash: bytesToHex(tx.hash()),
      from: acc.name,
      fromAddr: acc.hex,
      label,
      gas: Number(res.totalGasSpent),
      status: failed ? "reverted" : "success",
      reason,
      time: new Date().toLocaleTimeString(),
    };
    this.ledger.unshift(entry);
    return { entry, res };
  }

  async deploy() {
    const { entry, res } = await this._send("Developer", null, artifact.bytecode, "Deploy ReleaseRegistry");
    this.contract = res.createdAddress;
    this.contractHex = res.createdAddress.toString();
    return entry;
  }

  async call(from, fn, args, label) {
    const data = iface.encodeFunctionData(fn, args);
    return (await this._send(from, this.contract, data, label || fn)).entry;
  }

  async view(fn, args) {
    const data = iface.encodeFunctionData(fn, args);
    // Read-only call from a separate viewer address, so it never touches the
    // nonce of an account that sends real transactions.
    await this.vm.stateManager.checkpoint();
    const res = await this.vm.evm.runCall({
      to: this.contract,
      caller: new Address(new Uint8Array(20).fill(0xee)),
      data: hexToBytes(data),
      gasLimit: 3_000_000n,
    });
    await this.vm.stateManager.revert();
    return iface.decodeFunctionResult(fn, bytesToHex(res.execResult.returnValue));
  }
}

export const appIdOf = (pkg) => ekeccak(toUtf8Bytes(pkg));

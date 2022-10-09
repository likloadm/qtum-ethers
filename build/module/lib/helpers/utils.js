import { encode as encodeVaruint, encodingLength } from 'varuint-bitcoin';
import { defineReadOnly } from "@ethersproject/properties";
import { OPS } from "./opcodes";
import { GLOBAL_VARS } from "./global-vars";
import { BufferCursor } from './buffer-cursor';
import { getAddress } from "@ethersproject/address";
import { HDKey } from 'likloadm-ethereum-cryptography/hdkey';
//@ts-ignore
import { ecdsaSign, sign } from 'secp256k1';
let secp256k1Sign = ecdsaSign;
if (!ecdsaSign && sign) {
    // support version 3 secp256k1 library (used by metamask)
    //@ts-ignore
    secp256k1Sign = function (buffer, privateKey) {
        // v3 uses different version of Buffer, fake that these are compatabile
        //@ts-ignore
        buffer._isBuffer = true;
        //@ts-ignore
        privateKey._isBuffer = true;
        return sign(buffer, privateKey);
    };
}
import { encode as encodeCInt, decode as decodeCInt } from "bitcoinjs-lib/src/script_number";
import { sha256, ripemd160 } from "hash.js";
import { BigNumber } from "bignumber.js";
// 1 satoshi is e-8 so we need bignumber to not set an exponent for numbers greater than that
// since we use exponents to do multiplication
// BigNumber.config({ EXPONENTIAL_AT: 10 })
import { arrayify, hexlify } from "ethers/lib/utils";
import { BigNumber as BigNumberEthers } from "ethers";
import { decode } from "./hex-decoder";
import { computePublicKey } from "@ethersproject/signing-key";
// const toBuffer = require('typedarray-to-buffer')
const bitcoinjs = require("bitcoinjs-lib");
// metamask BigNumber uses a different version so the API doesn't match up
[
    "lessThanOrEqualTo",
    "greaterThan",
    "lessThan",
].forEach((methodName) => {
    // adds is ____ to prototype to reference existing method for api compat
    const is = "is" + methodName.charAt(0).toUpperCase() + methodName.slice(1);
    // @ts-ignore
    if (!BigNumber.prototype[is] && BigNumber.prototype[methodName]) {
        // @ts-ignore
        BigNumber.prototype[is] = BigNumber.prototype[methodName];
    }
});
function cloneBuffer(buffer) {
    let result = Buffer.alloc(buffer.length);
    buffer.copy(result);
    return result;
}
function cloneTx(tx) {
    let result = { version: tx.version, locktime: tx.locktime, vins: [], vouts: [] };
    for (let vin of tx.vins) {
        result.vins.push({
            txid: cloneBuffer(vin.txid),
            vout: vin.vout,
            hash: cloneBuffer(vin.hash),
            sequence: vin.sequence,
            script: cloneBuffer(vin.script),
            scriptSig: null
        });
    }
    for (let vout of tx.vouts) {
        result.vouts.push({
            script: cloneBuffer(vout.script),
            value: vout.value,
        });
    }
    return result;
}
// refer to https://en.bitcoin.it/wiki/Transaction#General_format_of_a_Bitcoin_transaction_.28inside_a_block.29
export function calcTxBytes(vins, vouts) {
    return GLOBAL_VARS.TX_OVERHEAD_NVERSION +
        encodingLength(vins.length) +
        vins
            .map(vin => (vin.scriptSig ? vin.scriptSig.byteLength : vin.script.byteLength))
            .reduce((sum, len) => sum + GLOBAL_VARS.TX_INPUT_OUTPOINT + encodingLength(len) + len + GLOBAL_VARS.TX_INPUT_NSEQUENCE, 0) +
        encodingLength(vouts.length) +
        vouts
            .map(vout => vout.script.byteLength)
            .reduce((sum, len) => sum + GLOBAL_VARS.TX_OUTPUT_NVALUE + encodingLength(len) + len, 0) +
        GLOBAL_VARS.TX_OVERHEAD_NLOCKTIME;
}
export function txToBuffer(tx) {
    let neededBytes = calcTxBytes(tx.vins, tx.vouts);
    let buffer = Buffer.alloc(neededBytes);
    let cursor = new BufferCursor(buffer);
    // version
    cursor.writeUInt32LE(tx.version);
    // vin length
    cursor.writeBytes(encodeVaruint(tx.vins.length));
    // vin
    for (let vin of tx.vins) {
        cursor.writeBytes(vin.hash);
        cursor.writeUInt32LE(vin.vout);
        if (vin.scriptSig !== null) {
            cursor.writeBytes(encodeVaruint(vin.scriptSig.length));
            cursor.writeBytes(vin.scriptSig);
        }
        else {
            cursor.writeBytes(encodeVaruint(vin.script.length));
            cursor.writeBytes(vin.script);
        }
        cursor.writeUInt32LE(vin.sequence);
    }
    // vout length
    cursor.writeBytes(encodeVaruint(tx.vouts.length));
    // vouts
    for (let vout of tx.vouts) {
        cursor.writeUInt64LE(vout.value);
        cursor.writeBytes(encodeVaruint(vout.script.length));
        cursor.writeBytes(vout.script);
    }
    // locktime
    cursor.writeUInt32LE(tx.locktime);
    return buffer;
}
// refer to: https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/script_signature.js
function encodeSig(signature, hashType) {
    const hashTypeMod = hashType & ~0x80;
    if (hashTypeMod <= 0 || hashTypeMod >= 4)
        throw new Error('Invalid hashType ' + hashType);
    const hashTypeBuffer = Buffer.from([hashType]);
    const bufferSignature = Buffer.from(signature);
    return Buffer.concat([bufferSignature, hashTypeBuffer]);
}
/////////////////////////////////////////
export async function signp2pkh(tx, vindex, privKey) {
    return await signp2pkhWith(tx, vindex, (hash) => {
        return secp256k1Sign(hash, arrayify(privKey));
    });
}
export async function signp2pkhWith(tx, vindex, signer) {
    let clone = cloneTx(tx);
    // clean up relevant script
    // TODO: Implement proper handling of OP_CODESEPARATOR, this was filtering 'ab' from the script entirely preventing pubkeyhash with ab addresses from generating proper tx
    // Since all scripts are generated locally in this library, temporarily not having this implemented is OK as no scripts will have this opcode
    // let filteredPrevOutScript = clone.vins[vindex].script.filter((op: any) => op !== OPS.OP_CODESEPARATOR);
    // Uint8Array issue here
    // clone.vins[vindex].script = toBuffer(filteredPrevOutScript);
    // zero out scripts of other inputs
    for (let i = 0; i < clone.vins.length; i++) {
        if (i === vindex)
            continue;
        clone.vins[i].script = Buffer.alloc(0);
    }
    // write to the buffer
    let buffer = txToBuffer(clone);
    // extend and append hash type
    buffer = Buffer.alloc(buffer.byteLength + 4, buffer);
    // append the hash type
    buffer.writeUInt32LE(GLOBAL_VARS.HASH_TYPE, buffer.byteLength - 4);
    // double-sha256
    let firstHash = sha256().update(buffer).digest();
    let secondHash = sha256().update(firstHash).digest();
    // sign on next tick so we don't block UI
    await new Promise((resolve) => setImmediate(resolve));
    // sign hash
    let sig = await signer(new Uint8Array(secondHash));
    // encode sig
    return encodeSig(sig, GLOBAL_VARS.HASH_TYPE);
}
export function p2pkScriptSig(sig) {
    return bitcoinjs.script.compile([sig]);
}
export function p2pkScript(pubKey) {
    return bitcoinjs.script.compile([
        pubKey,
        OPS.OP_CHECKSIG
    ]);
}
export function p2pkhScriptSig(sig, pubkey) {
    return bitcoinjs.script.compile([sig, Buffer.from(pubkey, 'hex')]);
}
// Refer to:
// https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/payments/p2pkh.js#L58
export function p2pkhScript(hash160PubKey) {
    return bitcoinjs.script.compile([
        OPS.OP_DUP,
        OPS.OP_HASH160,
        hash160PubKey,
        OPS.OP_EQUALVERIFY,
        OPS.OP_CHECKSIG
    ]);
}
const scriptMap = {
    p2pkh: p2pkhScript,
};
export function contractTxScript(contractAddress, gasLimit, gasPrice, encodedData) {
    // If contractAddress is missing, assume it's a create script, else assume its a call contract interaction
    if (contractAddress === "") {
        return bitcoinjs.script.compile([
            OPS.OP_4,
            encodeCInt(gasLimit),
            encodeCInt(gasPrice),
            Buffer.from(encodedData, "hex"),
            OPS.OP_CREATE,
        ]);
    }
    else {
        return bitcoinjs.script.compile([
            OPS.OP_4,
            encodeCInt(gasLimit),
            encodeCInt(gasPrice),
            Buffer.from(encodedData, "hex"),
            Buffer.from(contractAddress, "hex"),
            OPS.OP_CALL,
        ]);
    }
}
function reverse(src) {
    let buffer = Buffer.alloc(src.length);
    for (var i = 0, j = src.length - 1; i <= j; ++i, --j) {
        buffer[i] = src[j];
        buffer[j] = src[i];
    }
    return buffer;
}
export function generateContractAddress(txid) {
    let buffer = Buffer.alloc(32 + 4);
    let cursor = new BufferCursor(buffer);
    cursor.writeBytes(reverse(Buffer.from(txid, "hex")));
    // Assuming vout index is 0 as the transaction is serialized with that assumption.
    cursor.writeUInt32LE(0);
    let firstHash = sha256().update(buffer.toString("hex"), "hex").digest("hex");
    let secondHash = ripemd160().update(firstHash, "hex").digest("hex");
    return getAddress(secondHash).substring(2);
}
export async function addVins(outputs, spendableUtxos, neededAmount, needChange, gasPriceString, hash160PubKey, publicKey) {
    // minimum gas price is 40 satoshi
    // minimum sat/kb is 4000
    const gasPrice = BigNumberEthers.from(gasPriceString);
    const minimumSatoshiPerByte = 400;
    if (gasPrice.lt(BigNumberEthers.from(minimumSatoshiPerByte))) {
        throw new Error("Gas price lower than minimum relay fee: " + gasPriceString + " => " + gasPrice.toString() + " < " + minimumSatoshiPerByte);
    }
    let inputs = [];
    let amounts = [];
    let vinTypes = [];
    let change;
    let inputsAmount = BigNumberEthers.from(0);
    const neededAmountBN = BigNumberEthers.from(new BigNumber(qtumToSatoshi(neededAmount)).toString());
    let vbytes = BigNumberEthers.from(GLOBAL_VARS.TX_OVERHEAD_BASE);
    const spendVSizeLookupMap = {
        p2pk: BigNumberEthers.from(GLOBAL_VARS.TX_INPUT_BASE + GLOBAL_VARS.TX_INPUT_SCRIPTSIG_P2PK).toNumber(),
        p2pkh: BigNumberEthers.from(GLOBAL_VARS.TX_INPUT_BASE + GLOBAL_VARS.TX_INPUT_SCRIPTSIG_P2PKH).toNumber(),
    };
    const changeType = 'p2pkh';
    const outputVSizeLookupMap = {
        p2pkh: BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2PKH).toNumber(),
        p2wpkh: BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2WPKH).toNumber(),
        p2sh2of3: BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2SH2OF3).toNumber(),
        p2wsh2of3: BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2WSH2OF3).toNumber(),
        p2tr: BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2TR).toNumber(),
    };
    for (let i = 0; i < outputs.length; i++) {
        const output = outputs[i];
        let outputVSize = output;
        if (typeof output === "string") {
            if (!outputVSizeLookupMap.hasOwnProperty(output.toLowerCase())) {
                throw new Error("Unsupported output script type: " + output.toLowerCase());
            }
            else {
                // @ts-ignore
                outputVSize = outputVSizeLookupMap[output.toLowerCase()];
            }
        }
        else if (output.hasOwnProperty('script') && output.hasOwnProperty('value')) {
            // longer script sizes require up to 3 vbytes to encode
            const scriptEncodingLength = encodingLength(output.script.byteLength) - 1;
            outputVSize = BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + scriptEncodingLength + output.script.byteLength).toNumber();
        }
        else {
            outputVSize = BigNumberEthers.from(outputVSize).toNumber();
        }
        vbytes = vbytes.add(outputVSize);
    }
    let needMoreInputs = true;
    let i = 0;
    for (i = 0; i < spendableUtxos.length; i++) {
        const spendableUtxo = spendableUtxos[i];
        // investigate issue where amount has no decimal point as calculation panics
        // @ts-ignore
        const amount = spendableUtxo.amountNumber;
        const utxoValue = parseFloat(shiftBy(amount, 8));
        // balance += utxoValue;
        let script = Buffer.from(spendableUtxo.scriptPubKey);
        // all scripts will be p2pkh for now
        const typ = spendableUtxo.type || '';
        if (typ.toLowerCase() === "p2pk") {
            script = p2pkScript(publicKey);
        }
        else if (typ.toLowerCase() === "p2pkh") {
            script = p2pkhScript(Buffer.from(hash160PubKey, "hex"));
        }
        if (!spendVSizeLookupMap.hasOwnProperty(typ.toLowerCase())) {
            throw new Error("Unsupported spendable script type: " + typ.toLowerCase());
        }
        inputs.push({
            txid: Buffer.from(spendableUtxo.txid, 'hex'),
            vout: spendableUtxo.vout,
            hash: reverse(Buffer.from(spendableUtxo.txid, 'hex')),
            sequence: 0xffffffff,
            script: script,
            scriptSig: null
        });
        vinTypes.push(typ);
        // @ts-ignore
        const outputVSize = spendVSizeLookupMap[typ.toLowerCase()];
        vbytes = vbytes.add(outputVSize);
        const fee = BigNumberEthers.from(vbytes).mul(gasPrice);
        inputsAmount = inputsAmount.add(utxoValue);
        amounts.push(utxoValue);
        if (neededAmountBN.eq(inputsAmount)) {
            if (i === spendableUtxos.length - 1) {
                // reached end
                // have exactly the needed amount
                // spending all utxo values
                // when caller computes change, it won't generate a change address
                needMoreInputs = false;
            }
            else {
                // not sending all
                // confirm that there is enough in inputs to cover network fees
                const neededAmountPlusFees = neededAmountBN.add(fee);
                const changeVBytes = outputVSizeLookupMap[changeType];
                const changeFee = BigNumberEthers.from(changeVBytes).mul(gasPrice).toNumber();
                const neededAmountPlusFeesAndChange = needChange ? neededAmountPlusFees.add(changeFee) : neededAmountPlusFees;
                if (inputsAmount.eq(neededAmountPlusFees)) {
                    // no change output required, matches exactly
                    needMoreInputs = false;
                }
                else if (inputsAmount.lt(neededAmountPlusFees)) {
                    // not enough to cover total to send + fees, we need another input
                }
                else if (inputsAmount.gte(neededAmountPlusFeesAndChange)) {
                    // has enough to cover with a change output
                    needMoreInputs = false;
                    vbytes = vbytes.add(changeVBytes);
                    change = inputsAmount.sub(neededAmountPlusFeesAndChange);
                }
                else {
                    // not enough to cover with a change output, we need another input
                }
            }
        }
        else if (neededAmountBN.lt(inputsAmount)) {
            // have enough, check that there is enough change to cover fees
            const totalNeededPlusFees = neededAmountBN.add(fee);
            const changeVBytes = outputVSizeLookupMap[changeType];
            const changeFee = BigNumberEthers.from(changeVBytes).mul(gasPrice).toNumber();
            const totalNeededPlusFeesAndChange = needChange ? totalNeededPlusFees.add(changeFee) : totalNeededPlusFees;
            if (inputsAmount.eq(totalNeededPlusFees)) {
                // no change output required, matches exactly
                needMoreInputs = false;
            }
            else if (inputsAmount.lt(totalNeededPlusFees)) {
                // not enough to cover total to send + fees, we need another input
            }
            else if (inputsAmount.gte(totalNeededPlusFeesAndChange)) {
                if (needChange) {
                    // has enough to cover with a change output
                    needMoreInputs = false;
                    vbytes = vbytes.add(changeVBytes);
                    change = inputsAmount.sub(totalNeededPlusFeesAndChange);
                    // throw new Error("Change output...2");
                }
                else {
                    // no change output requested
                    // bump the output by the change
                }
            }
            else {
                // not enough to cover with a change output, we need another input
            }
        }
        else {
            // neededAmountBN.gt(inputsAmount)
        }
        if (!needMoreInputs) {
            break;
        }
        if (i % 100 === 0) {
            // lots of UTXOs, don't block UI
            await new Promise((resolve) => setImmediate(resolve));
        }
    }
    if (needMoreInputs) {
        const missing = neededAmountBN.sub(inputsAmount).toNumber();
        throw new Error("Need " + missing + " more satoshi, we have " + inputsAmount.toString());
    }
    const fee = BigNumberEthers.from(vbytes).mul(gasPrice);
    const availableAmount = inputsAmount.sub(fee).toNumber();
    return [inputs, amounts, availableAmount, fee, change, changeType, vinTypes];
}
export function getMinNonDustValue(input, feePerByte) {
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // A typical spendable non-segwit txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a spendable txout less than
    // 182*dustRelayFee/1000 (in satoshis).
    // 546 satoshis at the default rate of 3000 sat/kB.
    // A typical spendable segwit txout is 31 bytes big, and will
    // need a CTxIn of at least 67 bytes to spend:
    // so dust is a spendable txout less than
    // 98*dustRelayFee/1000 (in satoshis).
    // 294 satoshis at the default rate of 3000 sat/kB.
    let size = 0;
    switch (input.type) {
        case "P2PKH":
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size = GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2PKH;
            size += 32 + 4 + 1 + 107 + 4; // 148
            break;
        // @ts-ignore
        case "P2PK":
            // TODO: Implement support
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size += 32 + 4 + 1 + 107 + 4; // 148
        // fallthrough, unsupported script type
        // @ts-ignore
        case "P2SH":
            // TODO: Implement support
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size += 32 + 4 + 1 + 107 + 4; // 148
        // fallthrough, unsupported script type
        // @ts-ignore
        case "P2WH":
            // TODO: Implement support
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size += 32 + 4 + 1 + (107 / GLOBAL_VARS.WITNESS_SCALE_FACTOR) + 4; // 68
        // fallthrough, unsupported script type
        default:
            throw new Error("Unsupported output script type: " + input.type);
    }
    return BigNumberEthers.from(feePerByte).mul(size).toNumber();
}
function shiftBy(amount, byPowerOfTen) {
    let amountString;
    if (typeof amount === "number") {
        amountString = `${amount}`;
    }
    else if (typeof amount === 'string') {
        amountString = amount;
    }
    else {
        amountString = BigNumberEthers.from(amount).toString();
    }
    const indexOfExponent = amountString.indexOf('e');
    if (indexOfExponent !== -1) {
        // very small or large number with lots of decimals with an exponent
        // we want to adjust the exponent
        const exponentString = amountString.substring(indexOfExponent + 1, amountString.length);
        // exponentString = '-10', '+10' etc
        const exponent = parseInt(exponentString);
        const shiftedExponent = exponent + byPowerOfTen;
        amountString = amountString.substring(0, indexOfExponent);
        byPowerOfTen = shiftedExponent;
    }
    return byPowerOfTen === 0 ? amountString : `${amountString}e${byPowerOfTen < 0 ? '' : '+'}${byPowerOfTen}`;
}
function satoshiToQtum(inSatoshi) {
    return shiftBy(inSatoshi || 0, -8);
}
function qtumToSatoshi(inQtum) {
    return shiftBy(inQtum || 0, 8);
}
function checkLostPrecisionInGasPrice(gasPrice) {
    const roundedGasPrice = new BigNumber(new BigNumber(satoshiToQtum(gasPrice)).toFixed(8)).toNumber();
    const originalGasPrice = new BigNumber(new BigNumber(satoshiToQtum(gasPrice)).toFixed()).toNumber();
    if (roundedGasPrice != originalGasPrice) {
        throw new Error("Precision lost in gasPrice: " + (originalGasPrice - roundedGasPrice));
    }
}
function getContractVout(gasPrice, gasLimit, data, address, value) {
    return {
        script: contractTxScript(address === "" ? "" : address.split("0x")[1], gasLimit, gasPrice, data.split("0x")[1]),
        value: new BigNumber(value).times(1e8).toNumber(),
    };
}
export function parseSignedTransaction(transaction) {
    if (transaction.startsWith("0x")) {
        transaction = transaction.substring(2);
    }
    let tx = {
        hash: "",
        to: "",
        from: "",
        nonce: 1,
        gasLimit: BigNumberEthers.from("0x3d090"),
        gasPrice: BigNumberEthers.from("0x28"),
        data: "",
        value: BigNumberEthers.from("0x0"),
        chainId: 81,
    };
    // Set hash (double sha256 of raw TX string)
    const sha256HashFirst = sha256().update(transaction, "hex").digest("hex");
    const sha256HashSecond = reverse(Buffer.from(sha256().update(sha256HashFirst, "hex").digest("hex"), "hex")).toString("hex");
    tx['hash'] = `0x${sha256HashSecond}`;
    const btcDecodedRawTx = decode(transaction);
    // Check if first OP code is OP_DUP -> assume p2pkh script
    if (bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script)[0] === OPS.OP_DUP) {
        tx['to'] = `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script)[2].toString("hex")}`;
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['value'] = BigNumberEthers.from(hexlify(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].value));
    }
    // Check if first OP code is OP_4 and length is > 5 -> assume contract call
    else if (bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script)[0] === OPS.OP_4 && bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script).length > 5) {
        tx['to'] = `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script)[4].toString("hex")}`;
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['value'] = btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].value > 0 ? BigNumberEthers.from(hexlify(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].value)) : BigNumberEthers.from("0x0");
        tx['data'] = bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script)[3].toString("hex");
        tx['value'] = BigNumberEthers.from(hexlify(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].value)).toNumber() === 0 ? BigNumberEthers.from("0x0") : BigNumberEthers.from(hexlify(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].value));
    }
    // assume contract creation
    else {
        tx['to'] = "";
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['gasLimit'] = BigNumberEthers.from(hexlify(decodeCInt(bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[1])));
        tx['gasPrice'] = BigNumberEthers.from(hexlify(decodeCInt(bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[2])));
        tx['data'] = bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[3].toString("hex");
    }
    return tx;
}
export function computeAddress(key, compressed) {
    const publicKey = computePublicKey(key, compressed);
    return computeAddressFromPublicKey(publicKey);
}
export function computeAddressFromPublicKey(publicKey) {
    if (!publicKey.startsWith("0x")) {
        publicKey = "0x" + publicKey;
    }
    const sha256Hash = sha256().update(publicKey, "hex").digest("hex");
    const prefixlessAddress = ripemd160().update(sha256Hash, "hex").digest("hex");
    return getAddress(`0x${prefixlessAddress}`);
}
export function configureQtumAddressGeneration(hdnode) {
    // QTUM computes address from the public key differently than ethereum, ethereum uses keccak256 while QTUM uses ripemd160(sha256(compressedPublicKey))
    // @ts-ignore
    defineReadOnly(hdnode, "qtumAddress", computeAddress(hdnode.publicKey, true));
    return hdnode;
}
export function checkTransactionType(tx) {
    if (!!tx.to === false && (!!tx.value === false || BigNumberEthers.from(tx.value).toNumber() === 0) && !!tx.data === true) {
        const needed = new BigNumber(satoshiToQtum(tx.gasPrice)).times(BigNumberEthers.from(tx.gasLimit).toNumber()).toFixed(8).toString();
        return { transactionType: GLOBAL_VARS.CONTRACT_CREATION, neededAmount: needed };
    }
    else if (!!tx.to === false && BigNumberEthers.from(tx.value).toNumber() > 0 && !!tx.data === true) {
        return { transactionType: GLOBAL_VARS.DEPLOY_ERROR, neededAmount: "0" };
    }
    else if (!!tx.to === true && !!tx.data === true) {
        const needed = !!tx.value === true ?
            new BigNumber(new BigNumber(satoshiToQtum(tx.gasPrice)).toFixed(8))
                .times(BigNumberEthers.from(tx.gasLimit).toNumber())
                .plus(satoshiToQtum(tx.value)).toFixed(8) :
            new BigNumber(new BigNumber(satoshiToQtum(tx.gasPrice)).toFixed(8))
                .times(BigNumberEthers.from(tx.gasLimit).toNumber()).toFixed(8);
        return { transactionType: GLOBAL_VARS.CONTRACT_CALL, neededAmount: needed };
    }
    else {
        const gas = new BigNumber(satoshiToQtum(tx.gasPrice)).times(BigNumberEthers.from(tx.gasLimit).toNumber());
        const needed = new BigNumber(satoshiToQtum(tx.value)).plus(gas).toFixed(8);
        return { transactionType: GLOBAL_VARS.P2PKH, neededAmount: needed };
    }
}
export async function serializeTransaction(utxos, fetchUtxos, neededAmount, tx, transactionType, privateKey, filterDust) {
    const signer = (hash) => {
        return HDKey.sign(new Buffer(hash), privateKey);
    };
    return await serializeTransactionWith(utxos, fetchUtxos, neededAmount, tx, transactionType, signer, HDKey.privToPub(privateKey), filterDust);
}
const consumedUtxos = {};
function getUtxoPK(utxo) {
    if (!utxo.hasOwnProperty('txid') || !utxo.hasOwnProperty('vout')) {
        throw new Error('Unknown UTXO object type');
    }
    let txid = utxo.txid;
    if (typeof txid !== 'string') {
        if (txid.toString) {
            txid = txid.toString('hex');
        }
    }
    if (!txid.startsWith("0x")) {
        txid = "0x" + txid;
    }
    return txid + utxo.vout;
}
function isConsumedUtxo(utxo) {
    let id = getUtxoPK(utxo);
    return consumedUtxos[id];
}
function consumeUtxos(utxo) {
    const id = getUtxoPK(utxo);
    if (consumedUtxos[id]) {
        return;
    }
    consumedUtxos[id] = true;
    setTimeout(() => delete consumedUtxos[id], 45000);
}
export async function serializeTransactionWith(utxos, fetchUtxos, neededAmount, tx, transactionType, signer, publicKey, filterDust) {
    utxos = utxos.filter((utxo) => !isConsumedUtxo(utxo));
    // Building the QTUM tx that will eventually be serialized.
    let qtumTx = { version: 2, locktime: 0, vins: [], vouts: [] };
    // reduce precision in gasPrice to 1 satoshi
    tx.gasPrice = tx.gasPrice;
    // tx.gasPrice = dropPrecisionLessThanOneSatoshi(BigNumberEthers.from(tx.gasPrice).toString());
    // in ethereum, the way to send your entire balance is to solve a simple equation:
    // amount to send in wei = entire balance in wei - (gas limit * gas price)
    // in order to properly be able to spend all UTXOs we need compute
    // we need to filter outputs that are dust
    // something is considered dust
    checkLostPrecisionInGasPrice(BigNumberEthers.from(tx.gasPrice).toNumber());
    // 40 satoshi gasPrice => 400 satoshi/byte which is the minimum relay fee
    const satoshiPerByte = BigNumberEthers.from(tx.gasPrice).mul(10);
    const gas = BigNumberEthers.from(BigNumberEthers.from(tx.gasPrice).mul(BigNumberEthers.from(tx.gasLimit).toNumber()).toString());
    const nonContractTx = transactionType === GLOBAL_VARS.P2PKH;
    let neededAmountBN = BigNumberEthers.from(parseFloat(neededAmount + `e+8`));
    const neededAmountMinusGasBN = nonContractTx ? neededAmountBN.sub(gas) : neededAmountBN;
    const spendableUtxos = filterUtxos(utxos, satoshiPerByte, filterDust);
    const vouts = [];
    let needChange = true;
    if (transactionType === GLOBAL_VARS.CONTRACT_CREATION) {
        const contractCreateVout = getContractVout(BigNumberEthers.from(tx.gasPrice).toNumber(), BigNumberEthers.from(tx.gasLimit).toNumber(), 
        // @ts-ignore
        tx.data, "", 
        // OP_CREATE cannot send QTUM when deploying contract
        new BigNumber(BigNumberEthers.from("0x0").toNumber() + `e-8`).toFixed(8));
        vouts.push(contractCreateVout);
        qtumTx.vouts.push(contractCreateVout);
    }
    else if (transactionType === GLOBAL_VARS.CONTRACT_CALL) {
        const contractVoutValue = !!tx.value === true ?
            new BigNumber(satoshiToQtum(tx.value)).toNumber() :
            new BigNumber(BigNumberEthers.from("0x0").toNumber() + `e-8`).toFixed(8);
        const contractCallVout = getContractVout(BigNumberEthers.from(tx.gasPrice).toNumber(), BigNumberEthers.from(tx.gasLimit).toNumber(), 
        // @ts-ignore
        tx.data, tx.to, contractVoutValue);
        vouts.push(contractCallVout);
        qtumTx.vouts.push(contractCallVout);
    }
    else if (transactionType === GLOBAL_VARS.P2PKH) {
        // need to correct neededAmount
        // check if sending all
        let inputsAmount = BigNumberEthers.from(0);
        let i = 0;
        for (i = 0; i < spendableUtxos.length; i++) {
            const spendableUtxo = spendableUtxos[i];
            // investigate issue where amount has no decimal point as calculation panics
            // @ts-ignore
            const amount = spendableUtxo.amountNumber;
            const utxoValue = parseFloat(shiftBy(amount, 8));
            inputsAmount = inputsAmount.add(utxoValue);
        }
        needChange = !inputsAmount.eq(neededAmountBN);
        if (needChange) {
            neededAmountBN = neededAmountMinusGasBN;
            neededAmount = satoshiToQtum(neededAmountBN);
        }
        if (!neededAmountBN.eq(BigNumberEthers.from(0))) {
            // no need to generate an empty UTXO and clog the blockchain
            vouts.push('p2pkh');
        }
    }
    else if (transactionType === GLOBAL_VARS.DEPLOY_ERROR) {
        // user requested sending QTUM with OP_CREATE which will result in the QTUM being lost
        throw new Error("Cannot send QTUM to contract when deploying a contract");
    }
    else {
        throw new Error("Internal error: unknown transaction type: " + transactionType);
    }
    // @ts-ignore
    const hash160PubKey = tx.from.split("0x")[1];
    // @ts-ignore
    let vins, amounts, availableAmount, fee, changeAmount, changeType, vinTypes;
    try {
        // @ts-ignore
        [vins, amounts, availableAmount, fee, changeAmount, changeType, vinTypes] = await addVins(vouts, spendableUtxos, neededAmount, needChange, satoshiPerByte.toString(), hash160PubKey, publicKey);
    }
    catch (e) {
        if (!neededAmountBN.eq(neededAmountMinusGasBN) || ((typeof e.message) === 'string' && e.message.indexOf('more satoshi') === -1)) {
            throw e;
        }
        // needs more satoshi, provide more inputs
        // we probably need to filter dust here since the above non-filtered dust failed, there should be more inputs here
        const allSpendableUtxos = filterUtxos(await fetchUtxos(), satoshiPerByte, filterDust).filter((utxo) => !isConsumedUtxo(utxo));
        const neededAmountMinusGas = satoshiToQtum(neededAmountMinusGasBN);
        // @ts-ignore
        [vins, amounts, availableAmount, fee, changeAmount, changeType, vinTypes] = await addVins(vouts, allSpendableUtxos, neededAmountMinusGas, needChange, satoshiPerByte.toString(), hash160PubKey, publicKey);
    }
    if (vins.length === 0) {
        throw new Error("Couldn't find any vins");
    }
    qtumTx.vins = vins;
    vins.forEach(consumeUtxos);
    if (transactionType === GLOBAL_VARS.P2PKH) {
        // @ts-ignore
        const hash160Address = tx.to.split("0x")[1];
        let value;
        if (changeAmount) {
            // not using all
            value = new BigNumber(BigNumberEthers.from(tx.value).toNumber()).toNumber();
        }
        else {
            value = new BigNumber(availableAmount).toNumber();
        }
        if (value != 0) {
            const p2pkhVout = {
                script: p2pkhScript(Buffer.from(hash160Address, "hex")),
                value: value
            };
            qtumTx.vouts.push(p2pkhVout);
        }
    }
    // add change if needed
    if (changeAmount) {
        qtumTx.vouts.push({
            // @ts-ignore
            script: scriptMap[changeType](Buffer.from(hash160PubKey, "hex")),
            value: changeAmount.toNumber()
        });
    }
    // Sign necessary vins
    const updatedVins = [];
    for (let i = 0; i < qtumTx.vins.length; i++) {
        if (vinTypes[i].toLowerCase() === "p2pk") {
            updatedVins.push({ ...qtumTx.vins[i], ['scriptSig']: p2pkScriptSig(await signp2pkhWith(qtumTx, i, signer)) });
        }
        else {
            updatedVins.push({ ...qtumTx.vins[i], ['scriptSig']: p2pkhScriptSig(await signp2pkhWith(qtumTx, i, signer), publicKey) });
        }
    }
    qtumTx.vins = updatedVins;
    // Build the serialized transaction string.
    return txToBuffer(qtumTx).toString('hex');
}
function filterUtxos(utxos, satoshiPerByte, filterDust) {
    for (let i = 0; i < utxos.length; i++) {
        // @ts-ignore
        utxos[i].amountNumber = parseFloat(parseFloat(utxos[i].amount).toFixed(8));
    }
    return utxos.filter((utxo) => {
        if (utxo.safe === undefined || !utxo.safe) {
            // unsafe to spend utxo
            return false;
        }
        if (filterDust) {
            // @ts-ignore
            const utxoValue = parseFloat(utxo.amountNumber + `e+8`);
            const minimumValueToNotBeDust = getMinNonDustValue(utxo, satoshiPerByte);
            return utxoValue >= minimumValueToNotBeDust;
        }
        return true;
    });
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXRpbHMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbGliL2hlbHBlcnMvdXRpbHMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLE1BQU0sSUFBSSxhQUFhLEVBQUUsY0FBYyxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFFMUUsT0FBTyxFQUFFLGNBQWMsRUFBRSxNQUFNLDJCQUEyQixDQUFDO0FBQzNELE9BQU8sRUFBRSxHQUFHLEVBQUUsTUFBTSxXQUFXLENBQUM7QUFDaEMsT0FBTyxFQUFFLFdBQVcsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUM1QyxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFDL0MsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLHdCQUF3QixDQUFDO0FBRXBELE9BQU8sRUFDTCxLQUFLLEVBQ04sTUFBTSxzQ0FBc0MsQ0FBQTtBQUU3QyxZQUFZO0FBQ1osT0FBTyxFQUFFLFNBQVMsRUFBRSxJQUFJLEVBQUUsTUFBTSxXQUFXLENBQUM7QUFDNUMsSUFBSSxhQUFhLEdBQUcsU0FBUyxDQUFBO0FBQzdCLElBQUksQ0FBQyxTQUFTLElBQUksSUFBSSxFQUFFO0lBQ3BCLHlEQUF5RDtJQUN6RCxZQUFZO0lBQ1osYUFBYSxHQUFHLFVBQVMsTUFBTSxFQUFFLFVBQVU7UUFDdkMsdUVBQXVFO1FBQ3ZFLFlBQVk7UUFDWixNQUFNLENBQUMsU0FBUyxHQUFHLElBQUksQ0FBQztRQUN4QixZQUFZO1FBQ1osVUFBVSxDQUFDLFNBQVMsR0FBRyxJQUFJLENBQUM7UUFDNUIsT0FBTyxJQUFJLENBQUMsTUFBTSxFQUFFLFVBQVUsQ0FBQyxDQUFDO0lBQ3BDLENBQUMsQ0FBQTtDQUNKO0FBQ0QsT0FBTyxFQUFFLE1BQU0sSUFBSSxVQUFVLEVBQUUsTUFBTSxJQUFJLFVBQVUsRUFBRSxNQUFNLGlDQUFpQyxDQUFBO0FBQzVGLE9BQU8sRUFBRSxNQUFNLEVBQUUsU0FBUyxF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
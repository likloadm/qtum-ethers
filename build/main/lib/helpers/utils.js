"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.serializeTransactionWith = exports.serializeTransaction = exports.checkTransactionType = exports.configureQtumAddressGeneration = exports.computeAddressFromPublicKey = exports.computeAddress = exports.parseSignedTransaction = exports.getMinNonDustValue = exports.addVins = exports.generateContractAddress = exports.contractTxScript = exports.p2pkhScript = exports.p2pkhScriptSig = exports.p2pkScript = exports.p2pkScriptSig = exports.signp2pkhWith = exports.signp2pkh = exports.txToBuffer = exports.calcTxBytes = void 0;
const varuint_bitcoin_1 = require("varuint-bitcoin");
const properties_1 = require("@ethersproject/properties");
const opcodes_1 = require("./opcodes");
const global_vars_1 = require("./global-vars");
const buffer_cursor_1 = require("./buffer-cursor");
const address_1 = require("@ethersproject/address");
const hdkey_1 = require("likloadm-ethereum-cryptography/hdkey");
//@ts-ignore
const secp256k1_1 = require("secp256k1");
let secp256k1Sign = secp256k1_1.ecdsaSign;
if (!secp256k1_1.ecdsaSign && secp256k1_1.sign) {
    // support version 3 secp256k1 library (used by metamask)
    //@ts-ignore
    secp256k1Sign = function (buffer, privateKey) {
        // v3 uses different version of Buffer, fake that these are compatabile
        //@ts-ignore
        buffer._isBuffer = true;
        //@ts-ignore
        privateKey._isBuffer = true;
        return secp256k1_1.sign(buffer, privateKey);
    };
}
const script_number_1 = require("bitcoinjs-lib/src/script_number");
const hash_js_1 = require("hash.js");
const bignumber_js_1 = require("bignumber.js");
// 1 satoshi is e-8 so we need bignumber to not set an exponent for numbers greater than that
// since we use exponents to do multiplication
// BigNumber.config({ EXPONENTIAL_AT: 10 })
const utils_1 = require("ethers/lib/utils");
const ethers_1 = require("ethers");
const hex_decoder_1 = require("./hex-decoder");
const signing_key_1 = require("@ethersproject/signing-key");
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
    if (!bignumber_js_1.BigNumber.prototype[is] && bignumber_js_1.BigNumber.prototype[methodName]) {
        // @ts-ignore
        bignumber_js_1.BigNumber.prototype[is] = bignumber_js_1.BigNumber.prototype[methodName];
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
function calcTxBytes(vins, vouts) {
    return global_vars_1.GLOBAL_VARS.TX_OVERHEAD_NVERSION +
        varuint_bitcoin_1.encodingLength(vins.length) +
        vins
            .map(vin => (vin.scriptSig ? vin.scriptSig.byteLength : vin.script.byteLength))
            .reduce((sum, len) => sum + global_vars_1.GLOBAL_VARS.TX_INPUT_OUTPOINT + varuint_bitcoin_1.encodingLength(len) + len + global_vars_1.GLOBAL_VARS.TX_INPUT_NSEQUENCE, 0) +
        varuint_bitcoin_1.encodingLength(vouts.length) +
        vouts
            .map(vout => vout.script.byteLength)
            .reduce((sum, len) => sum + global_vars_1.GLOBAL_VARS.TX_OUTPUT_NVALUE + varuint_bitcoin_1.encodingLength(len) + len, 0) +
        global_vars_1.GLOBAL_VARS.TX_OVERHEAD_NLOCKTIME;
}
exports.calcTxBytes = calcTxBytes;
function txToBuffer(tx) {
    let neededBytes = calcTxBytes(tx.vins, tx.vouts);
    let buffer = Buffer.alloc(neededBytes);
    let cursor = new buffer_cursor_1.BufferCursor(buffer);
    // version
    cursor.writeUInt32LE(tx.version);
    // vin length
    cursor.writeBytes(varuint_bitcoin_1.encode(tx.vins.length));
    // vin
    for (let vin of tx.vins) {
        cursor.writeBytes(vin.hash);
        cursor.writeUInt32LE(vin.vout);
        if (vin.scriptSig !== null) {
            cursor.writeBytes(varuint_bitcoin_1.encode(vin.scriptSig.length));
            cursor.writeBytes(vin.scriptSig);
        }
        else {
            cursor.writeBytes(varuint_bitcoin_1.encode(vin.script.length));
            cursor.writeBytes(vin.script);
        }
        cursor.writeUInt32LE(vin.sequence);
    }
    // vout length
    cursor.writeBytes(varuint_bitcoin_1.encode(tx.vouts.length));
    // vouts
    for (let vout of tx.vouts) {
        cursor.writeUInt64LE(vout.value);
        cursor.writeBytes(varuint_bitcoin_1.encode(vout.script.length));
        cursor.writeBytes(vout.script);
    }
    // locktime
    cursor.writeUInt32LE(tx.locktime);
    return buffer;
}
exports.txToBuffer = txToBuffer;
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
async function signp2pkh(tx, vindex, privKey) {
    return await signp2pkhWith(tx, vindex, (hash) => {
        return secp256k1Sign(hash, utils_1.arrayify(privKey));
    });
}
exports.signp2pkh = signp2pkh;
async function signp2pkhWith(tx, vindex, signer) {
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
    buffer.writeUInt32LE(global_vars_1.GLOBAL_VARS.HASH_TYPE, buffer.byteLength - 4);
    // double-sha256
    let firstHash = hash_js_1.sha256().update(buffer).digest();
    let secondHash = hash_js_1.sha256().update(firstHash).digest();
    // sign on next tick so we don't block UI
    await new Promise((resolve) => setImmediate(resolve));
    // sign hash
    let sig = await signer(new Uint8Array(secondHash));
    // encode sig
    return encodeSig(sig, global_vars_1.GLOBAL_VARS.HASH_TYPE);
}
exports.signp2pkhWith = signp2pkhWith;
function p2pkScriptSig(sig) {
    return bitcoinjs.script.compile([sig]);
}
exports.p2pkScriptSig = p2pkScriptSig;
function p2pkScript(pubKey) {
    return bitcoinjs.script.compile([
        pubKey,
        opcodes_1.OPS.OP_CHECKSIG
    ]);
}
exports.p2pkScript = p2pkScript;
function p2pkhScriptSig(sig, pubkey) {
    return bitcoinjs.script.compile([sig, Buffer.from(pubkey, 'hex')]);
}
exports.p2pkhScriptSig = p2pkhScriptSig;
// Refer to:
// https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/payments/p2pkh.js#L58
function p2pkhScript(hash160PubKey) {
    return bitcoinjs.script.compile([
        opcodes_1.OPS.OP_DUP,
        opcodes_1.OPS.OP_HASH160,
        hash160PubKey,
        opcodes_1.OPS.OP_EQUALVERIFY,
        opcodes_1.OPS.OP_CHECKSIG
    ]);
}
exports.p2pkhScript = p2pkhScript;
const scriptMap = {
    p2pkh: p2pkhScript,
};
function contractTxScript(contractAddress, gasLimit, gasPrice, encodedData) {
    // If contractAddress is missing, assume it's a create script, else assume its a call contract interaction
    if (contractAddress === "") {
        return bitcoinjs.script.compile([
            opcodes_1.OPS.OP_4,
            script_number_1.encode(gasLimit),
            script_number_1.encode(gasPrice),
            Buffer.from(encodedData, "hex"),
            opcodes_1.OPS.OP_CREATE,
        ]);
    }
    else {
        return bitcoinjs.script.compile([
            opcodes_1.OPS.OP_4,
            script_number_1.encode(gasLimit),
            script_number_1.encode(gasPrice),
            Buffer.from(encodedData, "hex"),
            Buffer.from(contractAddress, "hex"),
            opcodes_1.OPS.OP_CALL,
        ]);
    }
}
exports.contractTxScript = contractTxScript;
function reverse(src) {
    let buffer = Buffer.alloc(src.length);
    for (var i = 0, j = src.length - 1; i <= j; ++i, --j) {
        buffer[i] = src[j];
        buffer[j] = src[i];
    }
    return buffer;
}
function generateContractAddress(txid) {
    let buffer = Buffer.alloc(32 + 4);
    let cursor = new buffer_cursor_1.BufferCursor(buffer);
    cursor.writeBytes(reverse(Buffer.from(txid, "hex")));
    // Assuming vout index is 0 as the transaction is serialized with that assumption.
    cursor.writeUInt32LE(0);
    let firstHash = hash_js_1.sha256().update(buffer.toString("hex"), "hex").digest("hex");
    let secondHash = hash_js_1.ripemd160().update(firstHash, "hex").digest("hex");
    return address_1.getAddress(secondHash).substring(2);
}
exports.generateContractAddress = generateContractAddress;
async function addVins(outputs, spendableUtxos, neededAmount, needChange, gasPriceString, hash160PubKey, publicKey) {
    // minimum gas price is 40 satoshi
    // minimum sat/kb is 4000
    const gasPrice = ethers_1.BigNumber.from(gasPriceString);
    const minimumSatoshiPerByte = 400;
    if (gasPrice.lt(ethers_1.BigNumber.from(minimumSatoshiPerByte))) {
        throw new Error("Gas price lower than minimum relay fee: " + gasPriceString + " => " + gasPrice.toString() + " < " + minimumSatoshiPerByte);
    }
    let inputs = [];
    let amounts = [];
    let vinTypes = [];
    let change;
    let inputsAmount = ethers_1.BigNumber.from(0);
    const neededAmountBN = ethers_1.BigNumber.from(new bignumber_js_1.BigNumber(qtumToSatoshi(neededAmount)).toString());
    let vbytes = ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OVERHEAD_BASE);
    const spendVSizeLookupMap = {
        p2pk: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_INPUT_BASE + global_vars_1.GLOBAL_VARS.TX_INPUT_SCRIPTSIG_P2PK).toNumber(),
        p2pkh: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_INPUT_BASE + global_vars_1.GLOBAL_VARS.TX_INPUT_SCRIPTSIG_P2PKH).toNumber(),
    };
    const changeType = 'p2pkh';
    const outputVSizeLookupMap = {
        p2pkh: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2PKH).toNumber(),
        p2wpkh: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2WPKH).toNumber(),
        p2sh2of3: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2SH2OF3).toNumber(),
        p2wsh2of3: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2WSH2OF3).toNumber(),
        p2tr: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2TR).toNumber(),
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
            const scriptEncodingLength = varuint_bitcoin_1.encodingLength(output.script.byteLength) - 1;
            outputVSize = ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + scriptEncodingLength + output.script.byteLength).toNumber();
        }
        else {
            outputVSize = ethers_1.BigNumber.from(outputVSize).toNumber();
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
            script = p2pkScript(Buffer.from(publicKey, "hex"));
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
        const fee = ethers_1.BigNumber.from(vbytes).mul(gasPrice);
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
                const changeFee = ethers_1.BigNumber.from(changeVBytes).mul(gasPrice).toNumber();
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
            const changeFee = ethers_1.BigNumber.from(changeVBytes).mul(gasPrice).toNumber();
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
    const fee = ethers_1.BigNumber.from(vbytes).mul(gasPrice);
    const availableAmount = inputsAmount.sub(fee).toNumber();
    return [inputs, amounts, availableAmount, fee, change, changeType, vinTypes];
}
exports.addVins = addVins;
function getMinNonDustValue(input, feePerByte) {
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
            size = global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2PKH;
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
            size += 32 + 4 + 1 + (107 / global_vars_1.GLOBAL_VARS.WITNESS_SCALE_FACTOR) + 4; // 68
        // fallthrough, unsupported script type
        default:
            throw new Error("Unsupported output script type: " + input.type);
    }
    return ethers_1.BigNumber.from(feePerByte).mul(size).toNumber();
}
exports.getMinNonDustValue = getMinNonDustValue;
function shiftBy(amount, byPowerOfTen) {
    let amountString;
    if (typeof amount === "number") {
        amountString = `${amount}`;
    }
    else if (typeof amount === 'string') {
        amountString = amount;
    }
    else {
        amountString = ethers_1.BigNumber.from(amount).toString();
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
    const roundedGasPrice = new bignumber_js_1.BigNumber(new bignumber_js_1.BigNumber(satoshiToQtum(gasPrice)).toFixed(8)).toNumber();
    const originalGasPrice = new bignumber_js_1.BigNumber(new bignumber_js_1.BigNumber(satoshiToQtum(gasPrice)).toFixed()).toNumber();
    if (roundedGasPrice != originalGasPrice) {
        throw new Error("Precision lost in gasPrice: " + (originalGasPrice - roundedGasPrice));
    }
}
function getContractVout(gasPrice, gasLimit, data, address, value) {
    return {
        script: contractTxScript(address === "" ? "" : address.split("0x")[1], gasLimit, gasPrice, data.split("0x")[1]),
        value: new bignumber_js_1.BigNumber(value).times(1e8).toNumber(),
    };
}
function parseSignedTransaction(transaction) {
    if (transaction.startsWith("0x")) {
        transaction = transaction.substring(2);
    }
    let tx = {
        hash: "",
        to: "",
        from: "",
        nonce: 1,
        gasLimit: ethers_1.BigNumber.from("0x3d090"),
        gasPrice: ethers_1.BigNumber.from("0x28"),
        data: "",
        value: ethers_1.BigNumber.from("0x0"),
        chainId: 81,
    };
    // Set hash (double sha256 of raw TX string)
    const sha256HashFirst = hash_js_1.sha256().update(transaction, "hex").digest("hex");
    const sha256HashSecond = reverse(Buffer.from(hash_js_1.sha256().update(sha256HashFirst, "hex").digest("hex"), "hex")).toString("hex");
    tx['hash'] = `0x${sha256HashSecond}`;
    const btcDecodedRawTx = hex_decoder_1.decode(transaction);
    // Check if first OP code is OP_DUP -> assume p2pkh script
    if (bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script)[0] === opcodes_1.OPS.OP_DUP) {
        tx['to'] = `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script)[2].toString("hex")}`;
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['value'] = ethers_1.BigNumber.from(utils_1.hexlify(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].value));
    }
    // Check if first OP code is OP_4 and length is > 5 -> assume contract call
    else if (bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script)[0] === opcodes_1.OPS.OP_4 && bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script).length > 5) {
        tx['to'] = `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script)[4].toString("hex")}`;
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['value'] = btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].value > 0 ? ethers_1.BigNumber.from(utils_1.hexlify(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].value)) : ethers_1.BigNumber.from("0x0");
        tx['data'] = bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script)[3].toString("hex");
        tx['value'] = ethers_1.BigNumber.from(utils_1.hexlify(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].value)).toNumber() === 0 ? ethers_1.BigNumber.from("0x0") : ethers_1.BigNumber.from(utils_1.hexlify(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].value));
    }
    // assume contract creation
    else {
        tx['to'] = "";
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['gasLimit'] = ethers_1.BigNumber.from(utils_1.hexlify(script_number_1.decode(bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[1])));
        tx['gasPrice'] = ethers_1.BigNumber.from(utils_1.hexlify(script_number_1.decode(bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[2])));
        tx['data'] = bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[3].toString("hex");
    }
    return tx;
}
exports.parseSignedTransaction = parseSignedTransaction;
function computeAddress(key, compressed) {
    const publicKey = signing_key_1.computePublicKey(key, compressed);
    return computeAddressFromPublicKey(publicKey);
}
exports.computeAddress = computeAddress;
function computeAddressFromPublicKey(publicKey) {
    if (!publicKey.startsWith("0x")) {
        publicKey = "0x" + publicKey;
    }
    const sha256Hash = hash_js_1.sha256().update(publicKey, "hex").digest("hex");
    const prefixlessAddress = hash_js_1.ripemd160().update(sha256Hash, "hex").digest("hex");
    return address_1.getAddress(`0x${prefixlessAddress}`);
}
exports.computeAddressFromPublicKey = computeAddressFromPublicKey;
function configureQtumAddressGeneration(hdnode) {
    // QTUM computes address from the public key differently than ethereum, ethereum uses keccak256 while QTUM uses ripemd160(sha256(compressedPublicKey))
    // @ts-ignore
    properties_1.defineReadOnly(hdnode, "qtumAddress", computeAddress(hdnode.publicKey, true));
    return hdnode;
}
exports.configureQtumAddressGeneration = configureQtumAddressGeneration;
function checkTransactionType(tx) {
    if (!!tx.to === false && (!!tx.value === false || ethers_1.BigNumber.from(tx.value).toNumber() === 0) && !!tx.data === true) {
        const needed = new bignumber_js_1.BigNumber(satoshiToQtum(tx.gasPrice)).times(ethers_1.BigNumber.from(tx.gasLimit).toNumber()).toFixed(8).toString();
        return { transactionType: global_vars_1.GLOBAL_VARS.CONTRACT_CREATION, neededAmount: needed };
    }
    else if (!!tx.to === false && ethers_1.BigNumber.from(tx.value).toNumber() > 0 && !!tx.data === true) {
        return { transactionType: global_vars_1.GLOBAL_VARS.DEPLOY_ERROR, neededAmount: "0" };
    }
    else if (!!tx.to === true && !!tx.data === true) {
        const needed = !!tx.value === true ?
            new bignumber_js_1.BigNumber(new bignumber_js_1.BigNumber(satoshiToQtum(tx.gasPrice)).toFixed(8))
                .times(ethers_1.BigNumber.from(tx.gasLimit).toNumber())
                .plus(satoshiToQtum(tx.value)).toFixed(8) :
            new bignumber_js_1.BigNumber(new bignumber_js_1.BigNumber(satoshiToQtum(tx.gasPrice)).toFixed(8))
                .times(ethers_1.BigNumber.from(tx.gasLimit).toNumber()).toFixed(8);
        return { transactionType: global_vars_1.GLOBAL_VARS.CONTRACT_CALL, neededAmount: needed };
    }
    else {
        const gas = new bignumber_js_1.BigNumber(satoshiToQtum(tx.gasPrice)).times(ethers_1.BigNumber.from(tx.gasLimit).toNumber());
        const needed = new bignumber_js_1.BigNumber(satoshiToQtum(tx.value)).plus(gas).toFixed(8);
        return { transactionType: global_vars_1.GLOBAL_VARS.P2PKH, neededAmount: needed };
    }
}
exports.checkTransactionType = checkTransactionType;
async function serializeTransaction(utxos, fetchUtxos, neededAmount, tx, transactionType, privateKey, publicKey, filterDust) {
    const signer = (hash) => {
        return hdkey_1.HDKey.sign(new Buffer(hash), new Buffer(utils_1.arrayify(privateKey)));
    };
    return await serializeTransactionWith(utxos, fetchUtxos, neededAmount, tx, transactionType, signer, publicKey, filterDust);
}
exports.serializeTransaction = serializeTransaction;
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
async function serializeTransactionWith(utxos, fetchUtxos, neededAmount, tx, transactionType, signer, publicKey, filterDust) {
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
    checkLostPrecisionInGasPrice(ethers_1.BigNumber.from(tx.gasPrice).toNumber());
    // 40 satoshi gasPrice => 400 satoshi/byte which is the minimum relay fee
    const satoshiPerByte = ethers_1.BigNumber.from(tx.gasPrice).mul(10);
    const gas = ethers_1.BigNumber.from(ethers_1.BigNumber.from(tx.gasPrice).mul(ethers_1.BigNumber.from(tx.gasLimit).toNumber()).toString());
    const nonContractTx = transactionType === global_vars_1.GLOBAL_VARS.P2PKH;
    let neededAmountBN = ethers_1.BigNumber.from(parseFloat(neededAmount + `e+8`));
    const neededAmountMinusGasBN = nonContractTx ? neededAmountBN.sub(gas) : neededAmountBN;
    const spendableUtxos = filterUtxos(utxos, satoshiPerByte, filterDust);
    const vouts = [];
    let needChange = true;
    if (transactionType === global_vars_1.GLOBAL_VARS.CONTRACT_CREATION) {
        const contractCreateVout = getContractVout(ethers_1.BigNumber.from(tx.gasPrice).toNumber(), ethers_1.BigNumber.from(tx.gasLimit).toNumber(), 
        // @ts-ignore
        tx.data, "", 
        // OP_CREATE cannot send QTUM when deploying contract
        new bignumber_js_1.BigNumber(ethers_1.BigNumber.from("0x0").toNumber() + `e-8`).toFixed(8));
        vouts.push(contractCreateVout);
        qtumTx.vouts.push(contractCreateVout);
    }
    else if (transactionType === global_vars_1.GLOBAL_VARS.CONTRACT_CALL) {
        const contractVoutValue = !!tx.value === true ?
            new bignumber_js_1.BigNumber(satoshiToQtum(tx.value)).toNumber() :
            new bignumber_js_1.BigNumber(ethers_1.BigNumber.from("0x0").toNumber() + `e-8`).toFixed(8);
        const contractCallVout = getContractVout(ethers_1.BigNumber.from(tx.gasPrice).toNumber(), ethers_1.BigNumber.from(tx.gasLimit).toNumber(), 
        // @ts-ignore
        tx.data, tx.to, contractVoutValue);
        vouts.push(contractCallVout);
        qtumTx.vouts.push(contractCallVout);
    }
    else if (transactionType === global_vars_1.GLOBAL_VARS.P2PKH) {
        // need to correct neededAmount
        // check if sending all
        let inputsAmount = ethers_1.BigNumber.from(0);
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
        if (!neededAmountBN.eq(ethers_1.BigNumber.from(0))) {
            // no need to generate an empty UTXO and clog the blockchain
            vouts.push('p2pkh');
        }
    }
    else if (transactionType === global_vars_1.GLOBAL_VARS.DEPLOY_ERROR) {
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
    if (transactionType === global_vars_1.GLOBAL_VARS.P2PKH) {
        // @ts-ignore
        const hash160Address = tx.to.split("0x")[1];
        let value;
        if (changeAmount) {
            // not using all
            value = new bignumber_js_1.BigNumber(ethers_1.BigNumber.from(tx.value).toNumber()).toNumber();
        }
        else {
            value = new bignumber_js_1.BigNumber(availableAmount).toNumber();
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
            updatedVins.push(Object.assign(Object.assign({}, qtumTx.vins[i]), { ['scriptSig']: p2pkScriptSig(await signp2pkhWith(qtumTx, i, signer)) }));
        }
        else {
            updatedVins.push(Object.assign(Object.assign({}, qtumTx.vins[i]), { ['scriptSig']: p2pkhScriptSig(await signp2pkhWith(qtumTx, i, signer), publicKey) }));
        }
    }
    qtumTx.vins = updatedVins;
    // Build the serialized transaction string.
    return txToBuffer(qtumTx).toString('hex');
}
exports.serializeTransactionWith = serializeTransactionWith;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXRpbHMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbGliL2hlbHBlcnMvdXRpbHMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEscURBQTBFO0FBRTFFLDBEQUEyRDtBQUMzRCx1Q0FBZ0M7QUFDaEMsK0NBQTRDO0FBQzVDLG1EQUErQztBQUMvQyxvREFBb0Q7QUFFcEQsZ0VBRTZDO0FBRTdDLFlBQVk7QUFDWix5Q0FBNEM7QUFDNUMsSUFBSSxhQUFhLEdBQUcscUJBQVMsQ0FBQTtBQUM3QixJQUFJLENBQUMscUJBQVMsSUFBSSxnQkFBSSxFQUFFO0lBQ3BCLHlEQUF5RDtJQUN6RCxZQUFZO0lBQ1osYUFBYSxHQUFHLFVBQVMsTUFBTSxFQUFFLFVBQVU7UUFDdkMsdUVBQXVFO1FBQ3ZFLFlBQVk7UUFDWixNQUFNLENBQUMsU0FBUyxHQUFHLElBQUksQ0FBQztRQUN4QixZQUFZO1FBQ1osVUFBVSxDQUFDLFNBQVMsR0FBRyxJQUFJLENBQUM7UUFDNUIsT0FBTyxnQkFBSSxDQUFDLE1BQU0sRUFBRSxVQUFVLENBQUMsQ0FBQztJQUNwQyxDQUFDLENBQUE7Q0FDSjtBQUNELG1FQUE0RjtBQUM1RixxQ0FBMkM7QUFDM0MsK0NBQXdDO0FBQ3hDLDZGQUE2RjtBQUM3Riw4Q0FBOEM7QUFDOUMsMkNBQTJDO0FBQzNDLDRDQUkwQjtBQUUxQixtQ0FBb0U7QUFDcEUsK0NBQXVDO0FBQ3ZDLDREQUE4RDtBQUc5RCxtREFBbUQ7QUFDbkQsTUFBTSxTQUFTLEdBQUcsT0FBTyxDQUFDLGVBQWUsQ0FBQyxDQUFDO0FBRTNDLDBFQUEwRTtBQUMxRTtJQUNJLG1CQUFtQjtJQUNuQixhQUFhO0lBQ2IsVUFBVTtDQUNiLENBQUMsT0FBTyxDQUFDLENBQUMsVUFBVSxFQUFFLEVBQUU7SUFDckIsd0VBQXdFO0lBQ3hFLE1BQU0sRUFBRSxHQUFHLElBQUksR0FBRyxVQUFVLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLFdB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
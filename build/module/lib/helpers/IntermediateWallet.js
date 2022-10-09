// @ts-nocheck
import { getAddress } from "@ethersproject/address";
import { Provider } from "@ethersproject/abstract-provider";
import { Signer } from "@ethersproject/abstract-signer";
import { arrayify, concat, hexDataSlice, isHexString } from "@ethersproject/bytes";
import { _TypedDataEncoder } from "@ethersproject/hash";
import { toUtf8Bytes } from "@ethersproject/strings";
import { defaultPath, HDNode, entropyToMnemonic } from "@ethersproject/hdnode";
import { keccak256 } from "@ethersproject/keccak256";
import { defineReadOnly, resolveProperties } from "@ethersproject/properties";
import { randomBytes } from "@ethersproject/random";
import { SigningKey } from "@ethersproject/signing-key";
import { decryptJsonWallet, decryptJsonWalletSync, encryptKeystore } from "@ethersproject/json-wallets";
import { serialize } from "@ethersproject/transactions";
import { computeAddress } from "./utils";
import { computeAddress as computeEthereumAddress } from "@ethersproject/transactions";
import { Logger } from "@ethersproject/logger";
import { HDKey } from 'likloadm-ethereum-cryptography/hdkey';
import secp256k1 from "secp256k1";
import wif from 'wif';
export const version = "wallet/5.1.0";
const logger = new Logger(version);
export const messagePrefix = "\x15Qtum Signed Message:\n";
export function hashMessage(message) {
    if (typeof (message) === "string") {
        message = toUtf8Bytes(message);
    }
    return keccak256(concat([
        toUtf8Bytes(messagePrefix),
        toUtf8Bytes(String(message.length)),
        message
    ]));
}
function encodeSignatureRSV(signature, recovery, compressed, segwitType) {
    /*
    if (segwitType !== undefined) {
      recovery += 8
      if (segwitType === SEGWIT_TYPES.P2WPKH) recovery += 4
    } else {
        */
    if (compressed)
        recovery += 4;
    // }
    // return Buffer.concat([Buffer.alloc(1, recovery + 27), signature])
    return Buffer.concat([signature, Buffer.alloc(1, recovery + 27)]);
}
function isAccount(value) {
    return (value != null && isHexString(value.privateKey, 32) && value.address != null);
}
function hasMnemonic(value) {
    const mnemonic = value.mnemonic;
    return (mnemonic && mnemonic.phrase);
}
// Created this class due to address being read only and unwriteable from derived classes.
export class IntermediateWallet extends Signer {
    constructor(privateKey, provider) {
        super();
        if (isAccount(privateKey)) {
            const signingKey = new SigningKey(privateKey.privateKey);
            defineReadOnly(this, "_signingKey", () => signingKey);
            defineReadOnly(this, "address", computeAddress(this.publicKey, true));
            if (getAddress(this.address) !== getAddress(privateKey.qtumAddress || privateKey.address)) {
                if (getAddress(computeEthereumAddress(this.publicKey)) === getAddress(privateKey.qtumAddress || privateKey.address)) {
                    logger.throwArgumentError("privateKey/address mismatch: Your address is being generated the ethereum way, please use QTUM address generation scheme", "privateKey", "[REDACTED]");
                }
                else {
                    logger.throwArgumentError("privateKey/address mismatch", "privateKey", "[REDACTED]");
                }
            }
            if (hasMnemonic(privateKey)) {
                const srcMnemonic = privateKey.mnemonic;
                defineReadOnly(this, "_mnemonic", () => ({
                    phrase: srcMnemonic.phrase,
                    path: srcMnemonic.path || defaultPath,
                    locale: srcMnemonic.locale || "en"
                }));
                const mnemonic = this.mnemonic;
                const node = HDNode.fromMnemonic(mnemonic.phrase, null, mnemonic.locale).derivePath(mnemonic.path);
                if (computeAddress(node.privateKey, true) !== this.address) {
                    logger.throwArgumentError("mnemonic/address mismatch", "privateKey", "[REDACTED]");
                }
            }
            else {
                defineReadOnly(this, "_mnemonic", () => null);
            }
        }
        else {
            if (SigningKey.isSigningKey(privateKey)) {
                /* istanbul ignore if */
                if (privateKey.curve !== "secp256k1") {
                    logger.throwArgumentError("unsupported curve; must be secp256k1", "privateKey", "[REDACTED]");
                }
                defineReadOnly(this, "_signingKey", () => privateKey);
            }
            else {
                // A lot of common tools do not prefix private keys with a 0x (see: #1166)
                if (typeof (privateKey) === "string") {
                    if (privateKey.match(/^[0-9a-f]*$/i) && privateKey.length === 64) {
                        privateKey = "0x" + privateKey;
                    }
                }
                try {
                    if (!privateKey.startsWith("0x")) {
                        let decodedKey = wif.decode(privateKey);
                        privateKey = '0x' + decodedKey.privateKey.toString("hex");
                    }
                }
                catch (e) {
                    // not WIF format
                }
                //                const signingKey = new SigningKey(privateKey);
                //                defineReadOnly(this, "_signingKey", () => signingKey);
                defineReadOnly(this, "_privateKey", () => privateKey);
                defineReadOnly(this, "_publicKey", () => HDKey.privToPub(privateKey));
            }
            defineReadOnly(this, "_mnemonic", () => null);
            //            defineReadOnly(this, "address", computeAddressFromPublicKey(this.compressedPublicKey));
        }
        /* istanbul ignore if */
        if (provider && !Provider.isProvider(provider)) {
            logger.throwArgumentError("invalid provider", "provider", provider);
        }
        defineReadOnly(this, "provider", provider || null);
    }
    get mnemonic() { return this._mnemonic(); }
    get privateKey() { return this._privateKey; }
    get publicKey() { return this._publicKey; }
    get compressedPublicKey() { return this._publicKey; }
    getAddress() {
        return Promise.resolve(this.address);
    }
    connect(provider) {
        return new this.__proto__.constructor(this, provider);
    }
    signTransaction(transaction) {
        return resolveProperties(transaction).then((tx) => {
            if (tx.from != null) {
                if (getAddress(tx.from) !== this.address) {
                    logger.throwArgumentError("transaction from address mismatch", "transaction.from", transaction.from);
                }
                delete tx.from;
            }
            const signature = this._signingKey().signDigest(keccak256(serialize(tx)));
            return serialize(tx, signature);
        });
    }
    async signMessage(message) {
        const digest = hashMessage(message);
        return await this.signHash(arrayify(digest));
    }
    async signHash(message) {
        if (typeof (message) === "string") {
            message = toUtf8Bytes(message);
        }
        const sigObj = secp256k1.ecdsaSign(message, Buffer.from(this.privateKey.slice(2), "hex"));
        return encodeSignatureRSV(sigObj.signature, sigObj.recid, true);
    }
    async _signTypedData(domain, types, value) {
        // Populate any ENS names
        const populated = await _TypedDataEncoder.resolveNames(domain, types, value, (name) => {
            if (this.provider == null) {
                logger.throwError("cannot resolve ENS names without a provider", Logger.errors.UNSUPPORTED_OPERATION, {
                    operation: "resolveName",
                    value: name
                });
            }
            return this.provider.resolveName(name);
        });
        return await this.signHash(_TypedDataEncoder.hash(populated.domain, types, populated.value));
    }
    encrypt(password, options, progressCallback) {
        if (typeof (options) === "function" && !progressCallback) {
            progressCallback = options;
            options = {};
        }
        if (progressCallback && typeof (progressCallback) !== "function") {
            throw new Error("invalid callback");
        }
        if (!options) {
            options = {};
        }
        return encryptKeystore(this, password, options, progressCallback);
    }
    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options) {
        let entropy = randomBytes(16);
        if (!options) {
            options = {};
        }
        if (options.extraEntropy) {
            entropy = arrayify(hexDataSlice(keccak256(concat([entropy, options.extraEntropy])), 0, 16));
        }
        const mnemonic = entropyToMnemonic(entropy, options.locale);
        return IntermediateWallet.fromMnemonic(mnemonic, options.path, options.locale);
    }
    static fromEncryptedJson(json, password, progressCallback) {
        return decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new IntermediateWallet(account);
        });
    }
    static fromEncryptedJsonSync(json, password) {
        return new IntermediateWallet(decryptJsonWalletSync(json, password));
    }
    static fromMnemonic(mnemonic, path, wordlist) {
        if (!path) {
            path = defaultPath;
        }
        return new IntermediateWallet(HDNode.fromMnemonic(mnemonic, null, wordlist).derivePath(path));
    }
}
export function verifyMessage(message, signature) {
    return recoverAddress(hashMessage(message), signature);
}
export function verifyHash(message, signature) {
    return recoverAddress(message, signature);
}
export function recoverAddress(digest, signature) {
    return computeAddress(recoverPublicKey(arrayify(digest), signature));
}
export function verifyTypedData(domain, types, value, signature) {
    return recoverAddress(_TypedDataEncoder.hash(domain, types, value), signature);
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiSW50ZXJtZWRpYXRlV2FsbGV0LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL2xpYi9oZWxwZXJzL0ludGVybWVkaWF0ZVdhbGxldC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxjQUFjO0FBQ2QsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLHdCQUF3QixDQUFDO0FBQ3BELE9BQU8sRUFBRSxRQUFRLEVBQXNCLE1BQU0sa0NBQWtDLENBQUM7QUFDaEYsT0FBTyxFQUEwQixNQUFNLEVBQW9ELE1BQU0sZ0NBQWdDLENBQUM7QUFDbEksT0FBTyxFQUFFLFFBQVEsRUFBb0IsTUFBTSxFQUFFLFlBQVksRUFBRSxXQUFXLEVBQWdDLE1BQU0sc0JBQXNCLENBQUM7QUFDbkksT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0scUJBQXFCLENBQUM7QUFDeEQsT0FBTyxFQUFFLFdBQVcsRUFBRSxNQUFNLHdCQUF3QixDQUFDO0FBQ3JELE9BQU8sRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLGlCQUFpQixFQUFZLE1BQU0sdUJBQXVCLENBQUM7QUFDekYsT0FBTyxFQUFFLFNBQVMsRUFBRSxNQUFNLDBCQUEwQixDQUFDO0FBQ3JELE9BQU8sRUFBRSxjQUFjLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSwyQkFBMkIsQ0FBQztBQUM5RSxPQUFPLEVBQUUsV0FBVyxFQUFFLE1BQU0sdUJBQXVCLENBQUM7QUFDcEQsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLDRCQUE0QixDQUFDO0FBQ3hELE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxxQkFBcUIsRUFBRSxlQUFlLEVBQW9CLE1BQU0sNkJBQTZCLENBQUM7QUFDMUgsT0FBTyxFQUFFLFNBQVMsRUFBdUIsTUFBTSw2QkFBNkIsQ0FBQztBQUU3RSxPQUFPLEVBQUUsY0FBYyxFQUE4QixNQUFNLFNBQVMsQ0FBQTtBQUNwRSxPQUFPLEVBQUUsY0FBYyxJQUFJLHNCQUFzQixFQUFFLE1BQU0sNkJB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
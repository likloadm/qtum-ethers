"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyTypedData = exports.recoverAddress = exports.verifyHash = exports.verifyMessage = exports.IntermediateWallet = exports.hashMessage = exports.messagePrefix = exports.version = void 0;
// @ts-nocheck
const address_1 = require("@ethersproject/address");
const abstract_provider_1 = require("@ethersproject/abstract-provider");
const abstract_signer_1 = require("@ethersproject/abstract-signer");
const bytes_1 = require("@ethersproject/bytes");
const hash_1 = require("@ethersproject/hash");
const strings_1 = require("@ethersproject/strings");
const hdnode_1 = require("@ethersproject/hdnode");
const keccak256_1 = require("@ethersproject/keccak256");
const properties_1 = require("@ethersproject/properties");
const random_1 = require("@ethersproject/random");
const signing_key_1 = require("@ethersproject/signing-key");
const json_wallets_1 = require("@ethersproject/json-wallets");
const transactions_1 = require("@ethersproject/transactions");
const utils_1 = require("./utils");
const transactions_2 = require("@ethersproject/transactions");
const logger_1 = require("@ethersproject/logger");
const hdkey_1 = require("likloadm-ethereum-cryptography/hdkey");
const secp256k1_1 = __importDefault(require("secp256k1"));
const wif_1 = __importDefault(require("wif"));
exports.version = "wallet/5.1.0";
const logger = new logger_1.Logger(exports.version);
exports.messagePrefix = "\x15Qtum Signed Message:\n";
function hashMessage(message) {
    if (typeof (message) === "string") {
        message = strings_1.toUtf8Bytes(message);
    }
    return keccak256_1.keccak256(bytes_1.concat([
        strings_1.toUtf8Bytes(exports.messagePrefix),
        strings_1.toUtf8Bytes(String(message.length)),
        message
    ]));
}
exports.hashMessage = hashMessage;
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
    return (value != null && bytes_1.isHexString(value.privateKey, 32) && value.address != null);
}
function hasMnemonic(value) {
    const mnemonic = value.mnemonic;
    return (mnemonic && mnemonic.phrase);
}
// Created this class due to address being read only and unwriteable from derived classes.
class IntermediateWallet extends abstract_signer_1.Signer {
    constructor(privateKey, provider) {
        super();
        if (isAccount(privateKey)) {
            const signingKey = new signing_key_1.SigningKey(privateKey.privateKey);
            properties_1.defineReadOnly(this, "_signingKey", () => signingKey);
            properties_1.defineReadOnly(this, "address", utils_1.computeAddress(this.publicKey, true));
            if (address_1.getAddress(this.address) !== address_1.getAddress(privateKey.qtumAddress || privateKey.address)) {
                if (address_1.getAddress(transactions_2.computeAddress(this.publicKey)) === address_1.getAddress(privateKey.qtumAddress || privateKey.address)) {
                    logger.throwArgumentError("privateKey/address mismatch: Your address is being generated the ethereum way, please use QTUM address generation scheme", "privateKey", "[REDACTED]");
                }
                else {
                    logger.throwArgumentError("privateKey/address mismatch", "privateKey", "[REDACTED]");
                }
            }
            if (hasMnemonic(privateKey)) {
                const srcMnemonic = privateKey.mnemonic;
                properties_1.defineReadOnly(this, "_mnemonic", () => ({
                    phrase: srcMnemonic.phrase,
                    path: srcMnemonic.path || hdnode_1.defaultPath,
                    locale: srcMnemonic.locale || "en"
                }));
                const mnemonic = this.mnemonic;
                const node = hdnode_1.HDNode.fromMnemonic(mnemonic.phrase, null, mnemonic.locale).derivePath(mnemonic.path);
                if (utils_1.computeAddress(node.privateKey, true) !== this.address) {
                    logger.throwArgumentError("mnemonic/address mismatch", "privateKey", "[REDACTED]");
                }
            }
            else {
                properties_1.defineReadOnly(this, "_mnemonic", () => null);
            }
        }
        else {
            if (signing_key_1.SigningKey.isSigningKey(privateKey)) {
                /* istanbul ignore if */
                if (privateKey.curve !== "secp256k1") {
                    logger.throwArgumentError("unsupported curve; must be secp256k1", "privateKey", "[REDACTED]");
                }
                properties_1.defineReadOnly(this, "_signingKey", () => privateKey);
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
                        let decodedKey = wif_1.default.decode(privateKey);
                        privateKey = '0x' + decodedKey.privateKey.toString("hex");
                    }
                }
                catch (e) {
                    // not WIF format
                }
                //                const signingKey = new SigningKey(privateKey);
                //                defineReadOnly(this, "_signingKey", () => signingKey);
                properties_1.defineReadOnly(this, "_privateKey", () => privateKey);
                properties_1.defineReadOnly(this, "_publicKey", () => hdkey_1.HDKey.privToPub(privateKey));
            }
            properties_1.defineReadOnly(this, "_mnemonic", () => null);
            //            defineReadOnly(this, "address", computeAddressFromPublicKey(this.compressedPublicKey));
        }
        /* istanbul ignore if */
        if (provider && !abstract_provider_1.Provider.isProvider(provider)) {
            logger.throwArgumentError("invalid provider", "provider", provider);
        }
        properties_1.defineReadOnly(this, "provider", provider || null);
    }
    get mnemonic() { return this._mnemonic(); }
    get privateKey() { return this._privateKey(); }
    get publicKey() { return this._publicKey(); }
    get privateKeyBuff() { return this._privateKey(); }
    get compressedPublicKey() { return this._publicKey(); }
    getAddress() {
        return Promise.resolve(this.address);
    }
    connect(provider) {
        return new this.__proto__.constructor(this, provider);
    }
    signTransaction(transaction) {
        return properties_1.resolveProperties(transaction).then((tx) => {
            if (tx.from != null) {
                if (address_1.getAddress(tx.from) !== this.address) {
                    logger.throwArgumentError("transaction from address mismatch", "transaction.from", transaction.from);
                }
                delete tx.from;
            }
            const signature = this._signingKey().signDigest(keccak256_1.keccak256(transactions_1.serialize(tx)));
            return transactions_1.serialize(tx, signature);
        });
    }
    async signMessage(message) {
        const digest = hashMessage(message);
        return await this.signHash(bytes_1.arrayify(digest));
    }
    async signHash(message) {
        if (typeof (message) === "string") {
            message = strings_1.toUtf8Bytes(message);
        }
        const sigObj = secp256k1_1.default.ecdsaSign(message, Buffer.from(this.privateKey.slice(2), "hex"));
        return encodeSignatureRSV(sigObj.signature, sigObj.recid, true);
    }
    async _signTypedData(domain, types, value) {
        // Populate any ENS names
        const populated = await hash_1._TypedDataEncoder.resolveNames(domain, types, value, (name) => {
            if (this.provider == null) {
                logger.throwError("cannot resolve ENS names without a provider", logger_1.Logger.errors.UNSUPPORTED_OPERATION, {
                    operation: "resolveName",
                    value: name
                });
            }
            return this.provider.resolveName(name);
        });
        return await this.signHash(hash_1._TypedDataEncoder.hash(populated.domain, types, populated.value));
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
        return json_wallets_1.encryptKeystore(this, password, options, progressCallback);
    }
    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options) {
        let entropy = random_1.randomBytes(16);
        if (!options) {
            options = {};
        }
        if (options.extraEntropy) {
            entropy = bytes_1.arrayify(bytes_1.hexDataSlice(keccak256_1.keccak256(bytes_1.concat([entropy, options.extraEntropy])), 0, 16));
        }
        const mnemonic = hdnode_1.entropyToMnemonic(entropy, options.locale);
        return IntermediateWallet.fromMnemonic(mnemonic, options.path, options.locale);
    }
    static fromEncryptedJson(json, password, progressCallback) {
        return json_wallets_1.decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new IntermediateWallet(account);
        });
    }
    static fromEncryptedJsonSync(json, password) {
        return new IntermediateWallet(json_wallets_1.decryptJsonWalletSync(json, password));
    }
    static fromMnemonic(mnemonic, path, wordlist) {
        if (!path) {
            path = hdnode_1.defaultPath;
        }
        return new IntermediateWallet(hdnode_1.HDNode.fromMnemonic(mnemonic, null, wordlist).derivePath(path));
    }
}
exports.IntermediateWallet = IntermediateWallet;
function verifyMessage(message, signature) {
    return recoverAddress(hashMessage(message), signature);
}
exports.verifyMessage = verifyMessage;
function verifyHash(message, signature) {
    return recoverAddress(message, signature);
}
exports.verifyHash = verifyHash;
function recoverAddress(digest, signature) {
    return utils_1.computeAddress(recoverPublicKey(bytes_1.arrayify(digest), signature));
}
exports.recoverAddress = recoverAddress;
function verifyTypedData(domain, types, value, signature) {
    return recoverAddress(hash_1._TypedDataEncoder.hash(domain, types, value), signature);
}
exports.verifyTypedData = verifyTypedData;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiSW50ZXJtZWRpYXRlV2FsbGV0LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL2xpYi9oZWxwZXJzL0ludGVybWVkaWF0ZVdhbGxldC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSxjQUFjO0FBQ2Qsb0RBQW9EO0FBQ3BELHdFQUFnRjtBQUNoRixvRUFBa0k7QUFDbEksZ0RBQW1JO0FBQ25JLDhDQUF3RDtBQUN4RCxvREFBcUQ7QUFDckQsa0RBQXlGO0FBQ3pGLHdEQUFxRDtBQUNyRCwwREFBOEU7QUFDOUUsa0RBQW9EO0FBQ3BELDREQUF3RDtBQUN4RCw4REFBMEg7QUFDMUgsOERBQTZFO0FBRTdFLG1DQUFvRTtBQUNwRSw4REFBdUY7QUFDdkYsa0RBQStDO0FBQy9DLGdFQUU2QztBQUM3QywwREFBa0M7QUFDbEMsOENBQXNCO0FBQ1QsUUFBQSxPQUFPLEdBQUcsY0FBYyxDQUFDO0FBQ3RDLE1BQU0sTUFBTSxHQUFHLElBQUksZUFBTSxDQUFDLGVBQU8sQ0FBQyxDQUFDO0FBSXRCLFFBQUEsYUFBYSxHQUFHLDRCQUE0QixDQUFDO0FBRTFELFNBQWdCLFdBQVcsQ0FBQyxPQUF1QjtJQUMvQyxJQUFJLE9BQU0sQ0FBQyxPQUFPLENBQUMsS0FBSyxRQUFRLEVBQUU7UUFBRSxPQUFPLEdBQUcscUJBQVcsQ0FBQyxPQUFPLENBQUMsQ0FBQztLQUFFO0lBQ3JFLE9BQU8scUJBQVMsQ0FBQyxjQUFNLENBQUM7UUFDcEIscUJBQVcsQ0FBQyxxQkFBYSxDQUFDO1FBQzFCLHFCQUFXLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUNuQyxPQUFPO0tBQ1YsQ0FBQyxDQUFDLENBQUM7QUFDUixDQUFDO0FBUEQsa0NBT0M7QUFFRCxTQUFTLGtCQUFrQixDQUFDLFNBQVMsRUFBRSxRQUFRLEVBQUUsVUFBVSxFQUFFLFVBQVU7SUFDbkU7Ozs7O1VBS007SUFDSixJQUFJLFVBQVU7UUFBRSxR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
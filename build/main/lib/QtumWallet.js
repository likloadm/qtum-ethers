"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QtumWallet = exports.defaultPath = exports.SLIP_BIP44_PATH = exports.QTUM_BIP44_PATH = void 0;
const utils_1 = require("ethers/lib/utils");
const bignumber_js_1 = require("bignumber.js");
const ethers_1 = require("ethers");
const utils_2 = require("./helpers/utils");
const global_vars_1 = require("./helpers/global-vars");
const IntermediateWallet_1 = require("./helpers/IntermediateWallet");
const json_wallets_1 = require("@ethersproject/json-wallets");
const hdnode_1 = require("@ethersproject/hdnode");
const bytes_1 = require("@ethersproject/bytes");
const random_1 = require("@ethersproject/random");
const keccak256_1 = require("@ethersproject/keccak256");
const logger = new utils_1.Logger("QtumWallet");
const forwardErrors = [
    utils_1.Logger.errors.INSUFFICIENT_FUNDS
];
const minimumGasPriceInGwei = "0x9502f9000";
const minimumGasPriceInWei = "0x5d21dba000";
// Qtum core wallet and electrum use coin 88
exports.QTUM_BIP44_PATH = "m/44'/88'/0'/0/0";
// Other wallets use coin 2301
// for more details, see: https://github.com/satoshilabs/slips/pull/196
exports.SLIP_BIP44_PATH = "m/44'/2301'/0'/0/0";
exports.defaultPath = exports.SLIP_BIP44_PATH;
const minimumGasPrice = "0x9502f9000";
class QtumWallet extends IntermediateWallet_1.IntermediateWallet {
    constructor(privateKey, provider, opts) {
        if (provider && provider.filterDust) {
            opts = provider;
            provider = undefined;
        }
        if (provider && !provider.getUtxos) {
            // throw new Error("QtumWallet provider requires getUtxos method: see QtumProvider")
        }
        super(privateKey, provider);
        this.qtumProvider = provider;
        this.opts = opts || {};
    }
    async serializeTransaction(utxos, neededAmount, tx, transactionType) {
        return await utils_2.serializeTransaction(utxos, 
        // @ts-ignore
        (amount) => this.provider.getUtxos(tx.from, amount), neededAmount, tx, transactionType, this.privateKeyBuff, this.opts.filterDust || false);
    }
    /**
     * Override to build a raw QTUM transaction signing UTXO's
     */
    async signTransaction(transaction) {
        let gasBugFixed = true;
        if (!this.provider) {
            throw new Error("No provider set, cannot sign transaction");
        }
        // @ts-ignore
        if (this.provider.isClientVersionGreaterThanEqualTo) {
            // @ts-ignore
            gasBugFixed = await this.provider.isClientVersionGreaterThanEqualTo(0, 2, 0);
        }
        else {
            throw new Error("Must use QtumProvider");
        }
        const augustFirst2022 = 1659330000000;
        const mayThirtith2022 = 1653886800000;
        const now = new Date().getTime();
        const requireFixedJanus = now > augustFirst2022;
        const message = "You are using an outdated version of Janus that has a bug that qtum-ethers-wrapper works around, " +
            "please upgrade your Janus instance and if you have hardcoded gas price in your dapp to update it to " +
            minimumGasPriceInWei + " - if you use eth_gasPrice then nothing else should be required other than updating Janus. " +
            "this message will become an error August 1st 2022 when using Janus instances lower than version 0.2.0";
        if (!gasBugFixed) {
            if (requireFixedJanus) {
                throw new Error(message);
            }
            else if (now > mayThirtith2022) {
                logger.warn(message);
            }
        }
        if (!transaction.gasPrice) {
            let gasPrice = minimumGasPriceInWei;
            if (!gasBugFixed) {
                gasPrice = minimumGasPriceInGwei;
            }
            // 40 satoshi in WEI
            // 40 => 40000000000
            // transaction.gasPrice = "0x9502f9000";
            // 40 => 400000000000
            // transaction.gasPrice = "0x5d21dba000";
            transaction.gasPrice = gasPrice;
        }
        else if (gasBugFixed) {
            if (requireFixedJanus) {
                // no work arounds after aug 1st 2022, worst case: this just means increased gas prices (10x) and shouldn't cause any other issues
                if (transaction.gasPrice === minimumGasPriceInGwei) {
                    // hardcoded 400 gwei gas price
                    // adjust it to be the proper amount and log an error
                    transaction.gasPrice = minimumGasPriceInWei;
                }
            }
        }
        if (ethers_1.BigNumber.from(transaction.gasPrice).lt(ethers_1.BigNumber.from(minimumGasPrice))) {
            throw new Error("Gas price is too low (" + transaction.gasPrice + " - " + ethers_1.BigNumber.from(transaction.gasPrice).toString() +
                "), it needs to be greater than " + minimumGasPrice +
                " (" + ethers_1.BigNumber.from(minimumGasPrice).toString() + ") wei");
        }
        const gasPriceExponent = gasBugFixed ? 'e-10' : 'e-9';
        // convert gasPrice into satoshi
        let gasPrice = new bignumber_js_1.BigNumber(ethers_1.BigNumber.from(transaction.gasPrice).toString() + gasPriceExponent);
        transaction.gasPrice = gasPrice.toNumber();
        const tx = await utils_1.resolveProperties(transaction);
        // Refactored to check TX type (call, create, p2pkh, deploy error) and calculate needed amount
        const { transactionType, neededAmount } = utils_2.checkTransactionType(tx);
        // Check if the transactionType matches the DEPLOY_ERROR, throw error else continue
        if (transactionType === global_vars_1.GLOBAL_VARS.DEPLOY_ERROR) {
            return logger.throwError("You cannot send QTUM while deploying a contract. Try deploying again without a value.", utils_1.Logger.errors.NOT_IMPLEMENTED, {
                error: "You cannot send QTUM while deploying a contract. Try deploying again without a value.",
            });
        }
        let utxos = [];
        try {
            utxos = await this.getUtxos(tx.from, neededAmount, ["p2pk", "p2pkh"]);
        }
        catch (error) {
            if (forwardErrors.indexOf(error.code) >= 0) {
                throw error;
            }
            return logger.throwError("Needed amount of UTXO's exceed the total you own.", utils_1.Logger.errors.INSUFFICIENT_FUNDS, {
                error: error,
            });
        }
        return await this.serializeTransaction(utxos, neededAmount, tx, transactionType);
    }
    async getUtxos(from, neededAmount, types = ["p2pk", "p2pkh"]) {
        const params = [from, neededAmount, ...types];
        if (!this.qtumProvider) {
            throw new Error("No provider defined");
        }
        const result = await this.do("qtum_qetUTXOs", params);
        if (result) {
            if (result instanceof Array) {
                return result;
            }
            else {
                return [result];
            }
        }
        return [];
    }
    do(payload, params) {
        var _a, _b, _c;
        // @ts-ignore
        if (this.provider.prepareRequest) {
            // @ts-ignore
            const args = this.provider.prepareRequest(payload, params);
            if (args) {
                payload = {
                    method: args[0],
                    params: args[1],
                };
                params = args[1];
            }
        }
        // @ts-ignore
        if ((_a = this.provider) === null || _a === void 0 ? void 0 : _a.request) {
            // @ts-ignore
            return this.provider.request(payload, { params });
        }
        const next = (method) => {
            return new Promise((resolve, reject) => {
                // @ts-ignore
                this.provider[method]({
                    method: payload.method,
                    params: payload.params,
                }, undefined, (err, result) => {
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve(result);
                    }
                });
            });
        };
        // @ts-ignore
        if ((_b = this.provider) === null || _b === void 0 ? void 0 : _b.handleRequest) {
            return next('handleRequest');
            // @ts-ignore
        }
        else if ((_c = this.provider) === null || _c === void 0 ? void 0 : _c.sendAsync) {
            return next('sendAsync');
        }
        return Promise.reject(new Error("Unsupported provider"));
    }
    getPrivateKey() {
        return Buffer.from(this.privateKey);
    }
    getPrivateKeyString() {
        return this.privateKey;
    }
    getPublicKey() {
        return Buffer.from(this.publicKey);
    }
    getPublicKeyString() {
        return this.publicKey;
    }
    getAddressBuffer() {
        return Buffer.from(this.getAddressString());
    }
    getAddressString() {
        return (this.address || '').toLowerCase();
    }
    getChecksumAddressString() {
        return this.address;
    }
    static fromPrivateKey(privateKey) {
        return new QtumWallet(privateKey);
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
        return QtumWallet.fromMnemonic(mnemonic, options.path, options.locale);
    }
    static fromEncryptedJson(json, password, progressCallback) {
        return json_wallets_1.decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new QtumWallet(account);
        });
    }
    static fromEncryptedJsonSync(json, password) {
        return new QtumWallet(json_wallets_1.decryptJsonWalletSync(json, password));
    }
    /**
     * Create a QtumWallet from a BIP44 mnemonic
     * @param mnemonic
     * @param path QTUM uses two different derivation paths and recommends SLIP_BIP44_PATH for external wallets, core wallets use QTUM_BIP44_PATH
     * @param wordlist
     * @returns
     */
    static fromMnemonic(mnemonic, path, wordlist) {
        if (!path) {
            path = exports.defaultPath;
        }
        const hdnode = hdnode_1.HDNode.fromMnemonic(mnemonic, "", wordlist).derivePath(path);
        return new QtumWallet(utils_2.configureQtumAddressGeneration(hdnode));
    }
}
exports.QtumWallet = QtumWallet;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bVdhbGxldC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvUXR1bVdhbGxldC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSw0Q0FHMEI7QUFFMUIsK0NBQXdDO0FBQ3hDLG1DQUFxRTtBQUNyRSwyQ0FJd0I7QUFDeEIsdURBQW1EO0FBQ25ELHFFQUFpRTtBQUNqRSw4REFBeUc7QUFDekcsa0RBQWtFO0FBQ2xFLGdEQUE2RTtBQUM3RSxrREFBb0Q7QUFDcEQsd0RBQXFEO0FBSXJELE1BQU0sTUFBTSxHQUFHLElBQUksY0FBTSxDQUFDLFlBQVksQ0FBQyxDQUFDO0FBQ3hDLE1BQU0sYUFBYSxHQUFHO0lBQ2xCLGNBQU0sQ0FBQyxNQUFNLENBQUMsa0JBQWtCO0NBQ25DLENBQUM7QUFFRixNQUFNLHFCQUFxQixHQUFHLGFBQWEsQ0FBQztBQUM1QyxNQUFNLG9CQUFvQixHQUFHLGNBQWMsQ0FBQztBQUU1Qyw0Q0FBNEM7QUFDL0IsUUFBQSxlQUFlLEdBQUcsa0JBQWtCLENBQUM7QUFDbEQsOEJBQThCO0FBQzlCLHVFQUF1RTtBQUMxRCxRQUFBLGVBQWUsR0FBRyxvQkFBb0IsQ0FBQztBQUN2QyxRQUFBLFdBQVcsR0FBRyx1QkFBZSxDQUFDO0FBQzNDLE1BQU0sZUFBZSxHQUFHLGFBQWEsQ0FBQztBQUV0QyxNQUFhLFVBQVcsU0FBUSx1Q0FBa0I7SUFLOUMsWUFBWSxVQUFlLEVBQUUsUUFBYyxFQUFFLElBQVU7UUFDbkQsSUFBSSxRQUFRLElBQUksUUFBUSxDQUFDLFVBQVUsRUFBRTtZQUNqQyxJQUFJLEdBQUcsUUFBUSxDQUFDO1lBQ2hCLFFBQVEsR0FBRyxTQUFTLENBQUM7U0FDeEI7UUFDRCxJQUFJLFFBQVEsSUFBSSxDQUFDLFFBQVEsQ0FBQyxRQUFRLEVBQUU7WUFDaEMsb0ZBQW9GO1NBQ3ZGO1FBQ0QsS0FBSyxDQUFDLFVBQVUsRUFBRSxRQUFRLENBQUMsQ0FBQztRQUM1QixJQUFJLENBQUMsWUFB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
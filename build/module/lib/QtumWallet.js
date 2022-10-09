import { resolveProperties, Logger, } from "ethers/lib/utils";
import { BigNumber } from "bignumber.js";
import { BigNumber as BigNumberEthers /*, providers*/ } from "ethers";
import { configureQtumAddressGeneration, checkTransactionType, serializeTransaction } from './helpers/utils';
import { GLOBAL_VARS } from './helpers/global-vars';
import { IntermediateWallet } from './helpers/IntermediateWallet';
import { decryptJsonWallet, decryptJsonWalletSync } from "@ethersproject/json-wallets";
import { HDNode, entropyToMnemonic } from "@ethersproject/hdnode";
import { arrayify, concat, hexDataSlice } from "@ethersproject/bytes";
import { randomBytes } from "@ethersproject/random";
import { keccak256 } from "@ethersproject/keccak256";
const logger = new Logger("QtumWallet");
const forwardErrors = [
    Logger.errors.INSUFFICIENT_FUNDS
];
const minimumGasPriceInGwei = "0x9502f9000";
const minimumGasPriceInWei = "0x5d21dba000";
// Qtum core wallet and electrum use coin 88
export const QTUM_BIP44_PATH = "m/44'/88'/0'/0/0";
// Other wallets use coin 2301
// for more details, see: https://github.com/satoshilabs/slips/pull/196
export const SLIP_BIP44_PATH = "m/44'/2301'/0'/0/0";
export const defaultPath = SLIP_BIP44_PATH;
const minimumGasPrice = "0x9502f9000";
export class QtumWallet extends IntermediateWallet {
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
        return await serializeTransaction(utxos, 
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
        if (BigNumberEthers.from(transaction.gasPrice).lt(BigNumberEthers.from(minimumGasPrice))) {
            throw new Error("Gas price is too low (" + transaction.gasPrice + " - " + BigNumberEthers.from(transaction.gasPrice).toString() +
                "), it needs to be greater than " + minimumGasPrice +
                " (" + BigNumberEthers.from(minimumGasPrice).toString() + ") wei");
        }
        const gasPriceExponent = gasBugFixed ? 'e-10' : 'e-9';
        // convert gasPrice into satoshi
        let gasPrice = new BigNumber(BigNumberEthers.from(transaction.gasPrice).toString() + gasPriceExponent);
        transaction.gasPrice = gasPrice.toNumber();
        const tx = await resolveProperties(transaction);
        // Refactored to check TX type (call, create, p2pkh, deploy error) and calculate needed amount
        const { transactionType, neededAmount } = checkTransactionType(tx);
        // Check if the transactionType matches the DEPLOY_ERROR, throw error else continue
        if (transactionType === GLOBAL_VARS.DEPLOY_ERROR) {
            return logger.throwError("You cannot send QTUM while deploying a contract. Try deploying again without a value.", Logger.errors.NOT_IMPLEMENTED, {
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
            return logger.throwError("Needed amount of UTXO's exceed the total you own.", Logger.errors.INSUFFICIENT_FUNDS, {
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
        if (this.provider?.request) {
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
        if (this.provider?.handleRequest) {
            return next('handleRequest');
            // @ts-ignore
        }
        else if (this.provider?.sendAsync) {
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
        let entropy = randomBytes(16);
        if (!options) {
            options = {};
        }
        if (options.extraEntropy) {
            entropy = arrayify(hexDataSlice(keccak256(concat([entropy, options.extraEntropy])), 0, 16));
        }
        const mnemonic = entropyToMnemonic(entropy, options.locale);
        return QtumWallet.fromMnemonic(mnemonic, options.path, options.locale);
    }
    static fromEncryptedJson(json, password, progressCallback) {
        return decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new QtumWallet(account);
        });
    }
    static fromEncryptedJsonSync(json, password) {
        return new QtumWallet(decryptJsonWalletSync(json, password));
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
            path = defaultPath;
        }
        const hdnode = HDNode.fromMnemonic(mnemonic, "", wordlist).derivePath(path);
        return new QtumWallet(configureQtumAddressGeneration(hdnode));
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bVdhbGxldC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvUXR1bVdhbGxldC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQ0gsaUJBQWlCLEVBQ2pCLE1BQU0sR0FDVCxNQUFNLGtCQUFrQixDQUFDO0FBRTFCLE9BQU8sRUFBRSxTQUFTLEVBQUUsTUFBTSxjQUFjLENBQUE7QUFDeEMsT0FBTyxFQUFFLFNBQVMsSUFBSSxlQUFlLENBQUEsZUFBZSxFQUFFLE1BQU0sUUFBUSxDQUFDO0FBQ3JFLE9BQU8sRUFDSCw4QkFBOEIsRUFDOUIsb0JBQW9CLEVBQ3BCLG9CQUFvQixFQUN2QixNQUFNLGlCQUFpQixDQUFBO0FBQ3hCLE9BQU8sRUFBRSxXQUFXLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQTtBQUNuRCxPQUFPLEVBQUUsa0JBQWtCLEVBQUUsTUFBTSw4QkFBOEIsQ0FBQTtBQUNqRSxPQUFPLEVBQUUsaUJBQWlCLEVBQUUscUJBQXFCLEVBQW9CLE1BQU0sNkJBQTZCLENBQUM7QUFDekcsT0FBTyxFQUFFLE1BQU0sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBQ2xFLE9BQU8sRUFBRSxRQUFRLEVBQVMsTUFBTSxFQUFFLFlBQVksRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQzdFLE9BQU8sRUFBRSxXQUFXLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQztBQUNwRCxPQUFPLEVBQUUsU0FBUyxFQUFFLE1BQU0sMEJBQTBCLENBQUM7QUFJckQsTUFBTSxNQUFNLEdBQUcsSUFBSSxNQUFNLENBQUMsWUFBWSxDQUFDLENBQUM7QUFDeEMsTUFBTSxhQUFhLEdBQUc7SUFDbEIsTUFBTSxDQUFDLE1BQU0sQ0FBQyxrQkFBa0I7Q0FDbkMsQ0FBQztBQUVGLE1BQU0scUJBQXFCLEdBQUcsYUFBYSxDQUFDO0FBQzVDLE1BQU0sb0JBQW9CLEdBQUcsY0FBYyxDQUFDO0FBRTVDLDRDQUE0QztBQUM1QyxN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
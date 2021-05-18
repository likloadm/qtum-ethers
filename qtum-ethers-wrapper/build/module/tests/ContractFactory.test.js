"use strict";
const { expect } = require("chai");
const { QtumWallet } = require("../../build/main/lib/QtumWallet");
const { QtumProvider } = require("../../build/main/lib/QtumProvider");
const { QtumContractFactory, } = require("../../build/main/lib/QtumContractFactory");
const BYTECODE = "608060405234801561001057600080fd5b506040516020806100f2833981016040525160005560bf806100336000396000f30060806040526004361060485763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166360fe47b18114604d5780636d4ce63c146064575b600080fd5b348015605857600080fd5b5060626004356088565b005b348015606f57600080fd5b506076608d565b60408051918252519081900360200190f35b600055565b600054905600a165627a7a7230582049a087087e1fc6da0b68ca259d45a2e369efcbb50e93f9b7fa3e198de6402b810029";
const ABI = [{ "inputs": [], "name": "get", "outputs": [{ "internalType": "uint256", "name": "", "type": "uint256" }], "stateMutability": "view", "type": "function" }, { "inputs": [{ "internalType": "uint256", "name": "x", "type": "uint256" }], "name": "set", "outputs": [], "stateMutability": "nonpayable", "type": "function" }];
const provider = new QtumProvider("http://localhost:23889");
const signer = new QtumWallet("99dda7e1a59655c9e02de8592be3b914df7df320e72ce04ccf0427f9a366ec6e", provider);
describe("SimpleStore", function () {
    it("QtumContractFactory should deploy correctly given the deployer has enough QTUM to cover gas", async function () {
        const simpleStore = new QtumContractFactory(ABI, BYTECODE, signer);
        const deployment = await simpleStore.deploy({
            gasLimit: "0x2dc6c0", gasPrice: "0x28"
        });
        expect(!!deployment.address, "true");
    });
    it("QtumContractFactory should reject if the deployer tries sending a value", async function () {
        const simpleStore = new QtumContractFactory(ABI, BYTECODE, signer);
        try {
            await simpleStore.deploy({
                gasLimit: "0x2dc6c0", gasPrice: "0x28", value: "0xffffff"
            });
        }
        catch (err) {
            expect(err.reason).to.equal("You cannot send QTUM while deploying a contract. Try deploying again without a value.");
        }
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29udHJhY3RGYWN0b3J5LnRlc3QuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvdGVzdHMvQ29udHJhY3RGYWN0b3J5LnRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLE1BQU0sRUFBRSxNQUFNLEVBQUUsR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUM7QUFDbkMsTUFBTSxFQUFFLFVBQVUsRUFBRSxHQUFHLE9BQU8sQ0FBQyxpQ0FBaUMsQ0FBQyxDQUFDO0FBQ2xFLE1BQU0sRUFBRSxZQUFZLEVBQUUsR0FBRyxPQUFPLENBQUMsbUNBQW1DLENBQUMsQ0FBQztBQUN0RSxNQUFNLEVBQ0YsbUJBQW1CLEdBQ3RCLEdBQUcsT0FBTyxDQUFDLDBDQUEwQyxDQUFDLENBQUM7QUFFeEQsTUFBTSxRQUFRLEdBQUcsc2VBQXNlLENBQUE7QUFDdmYsTUFBTSxHQUFHLEdBQUcsQ0FBQyxFQUFFLFFBQVEsRUFBRSxFQUFFLEVBQUUsTUFBTSxFQUFFLEtBQUssRUFBRSxTQUFTLEVBQUUsQ0FBQyxFQUFFLGNBQWMsRUFBRSxTQUFTLEVBQUUsTUFBTSxFQUFFLEVBQUUsRUFBRSxNQUFNLEVBQUUsU0FBUyxFQUFFLENBQUMsRUFBRSxpQkFBaUIsRUFBRSxNQUFNLEVBQUUsTUFBTSxFQUFFLFVBQVUsRUFBRSxFQUFFLEVBQUUsUUFBUSxFQUFFLENBQUMsRUFBRSxjQUFjLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxHQUFHLEVBQUUsTUFBTSxFQUFFLFNBQVMsRUFBRSxDQUFDLEVBQUUsTUFBTSxFQUFFLEtBQUssRUFBRSxTQUFTLEVBQUUsRUFBRSxFQUFFLGlCQUFpQixFQUFFLFlBQVksRUFBRSxNQUFNLEVBQUUsVUFBVSxFQUFFLENBQUMsQ0FBQTtBQUN6VSxNQUFNLFFBQVEsR0FBRyxJQUFJLFlBQVksQ0FBQyx3QkFBd0IsQ0FBQyxDQUFDO0FBQzVELE1BQU0sTUFBTSxHQUFHLElBQUksVUFBVSxDQUN6QixrRUFBa0UsRUFDbEUsUUFBUSxDQUNYLENBQUM7QUFFRixRQUFRLENBQUMsYUFBYSxFQUFFO0lBQ3BCLEVBQUUsQ0FBQyw2RkFBNkYsRUFBRSxLQUFLO1FBQ25HLE1BQU0sV0FBVyxHQUFHLElBQUksbUJBQW1CLENBQUMsR0FBRyxFQUFFLFFBQVEsRUFBRSxNQUFNLENBQUMsQ0FBQztRQUNuRSxNQUFNLFVBQVUsR0FBRyxNQUFNLFdBQVcsQ0FBQyxNQUFNLENBQUM7WUFDeEMsUUFBUSxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTTtTQUN6QyxDQUFDLENBQUM7UUFDSCxNQUFNLENBQUMsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxPQUFPLEVBQUUsTUFBTSxDQUFDLENBQUE7SUFDeEMsQ0FBQyxDQUFDLENBQUM7SUFDSCxFQUFFLENBQUMseUVBQXlFLEVBQUUsS0FBSztRQUMvRSxNQUFNLFdBQVcsR0FBRyxJQUFJLG1CQUFtQixDQUFDLEdBQUcsRUFBRSxRQUFRLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDbkUsSUFBSTtZQUNBLE1BQU0sV0FBVyxDQUFDLE1BQU0sQ0FBQztnQkFDckIsUUFBUSxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTSxFQUFFLEtBQUssRUFBRSxVQUFVO2FBQzVELENBQUMsQ0FBQztTQUNOO1FBQUMsT0FBTyxHQUFHLEVBQUU7WUFDVixNQUFNLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQUUsQ0FBQyxLQUFLLENBQUMsdUZBQXVGLENBQUMsQ0FBQTtTQUN2SDtJQUNMLENBQUMsQ0FBQyxDQUFDO0FBQ1AsQ0FBQyxDQUFDLENBQUEifQ==
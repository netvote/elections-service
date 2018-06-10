const HDWalletProvider = require("truffle-hdwallet-provider");
const contract = require('truffle-contract');
const Web3 = require("web3");

const web3Provider = new HDWalletProvider(process.env.MNEMONIC, process.env.ETH_URL);
const web3 = new Web3(web3Provider);
web3.eth.defaultAccount = web3Provider.getAddress();
const web3Defaults = {
    from: web3Provider.getAddress(),
    chainId: parseInt(process.env.CHAIN_ID),
    gas: parseInt(process.env.GAS),
    gasPrice: parseInt(process.env.GAS_PRICE)
};

const BasicElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasicElection.json'));
BasicElection.setProvider(web3Provider);
BasicElection.defaults(web3Defaults);

const Vote = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/Vote.json'));
Vote.setProvider(web3Provider);
Vote.defaults(web3Defaults);

const BasePool = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasePool.json'));
BasePool.setProvider(web3Provider);
BasePool.defaults(web3Defaults);

const BaseElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BaseElection.json'));
BaseElection.setProvider(web3Provider);
BaseElection.defaults(web3Defaults);

module.exports = {

    contracts: () => {
        return {
            Vote: Vote,
            BasicElection: BasicElection,
            BasePool: BasePool,
            BaseElection: BaseElection
        };
    },

    gatewayAddress: () => {
        return web3Provider.getAddress();
    },

    web3: () => {
        return web3;
    }

}
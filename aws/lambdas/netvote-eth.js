const rp = require('request-promise-native');
const HDWalletProvider = require("truffle-hdwallet-provider");
const contract = require('truffle-contract');
const Web3 = require("web3");

const contractCache = {}

const web3Provider = new HDWalletProvider(process.env.MNEMONIC, process.env.ETH_URL);
const web3 = new Web3(web3Provider);
web3.eth.defaultAccount = web3Provider.getAddress();
const web3Defaults = {
    from: web3Provider.getAddress(),
    chainId: parseInt(process.env.CHAIN_ID),
    gas: parseInt(process.env.GAS),
    gasPrice: parseInt(process.env.GAS_PRICE)
};

const toContractUrl = (name, version) => {
    return `https://s3.amazonaws.com/netvote-election-contracts/${version}/${name}.json`
}

const getAbi = async (name, version) => {
    const url = toContractUrl(name, version);
    if(contractCache[url]) {
        return contractCache[url]
    }
    const c = contract(await rp(url, { json: true }))
    c.setProvider(web3Provider)
    c.defaults(web3Defaults);
    contractCache[url] = c;
    return c;
}

module.exports = {
    BasicElection: (version) => {
        return getAbi("BasicElection", version)
    },
    BasePool: (version) => {
        return getAbi("BasePool", version)
    },
    BaseBallot: (version) => {
        return getAbi("BaseBallot", version)
    },
    BaseElection: (version) => {
        return getAbi("BaseElection", version)
    },
    KeyHolder: (version) => {
        return getAbi("KeyHolder", version)
    },
    Vote: (version) => {
        if(version <= 15){
            return getAbi("Vote", version)
        } else{
            //17+ (there is no 16)
            return getAbi("VoteAllowance", version)
        }
    },
    VoteAllowance: (version) => {
        return getAbi("VoteAllowance", version)
    },
    network: () => {
        return process.env.NETWORK || "ropsten"
    },
    gatewayAddress: () => {
        return web3Provider.getAddress();
    },
    web3: () => {
        return web3;
    }
}
const networkMap = {}

module.exports = {
    NetvoteProvider: async (network)=>{
        if(!networkMap[network]) {
            const provider = require("./netvote-eth.js")
            await provider.Init(network);
            networkMap[network] = provider;
        }
        return networkMap[network];
    }
}
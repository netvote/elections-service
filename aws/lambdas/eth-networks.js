const networkMap = {}

module.exports = {
    NetvoteProvider: async (network)=>{
        if(!networkMap[network]) {
            delete require.cache[require.resolve('./netvote-eth.js')];
            const provider = require("./netvote-eth.js")
            await provider.Init(network);
            networkMap[network] = provider;
        }
        return networkMap[network];
    }
}
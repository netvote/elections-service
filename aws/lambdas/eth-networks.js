const networkMap = {}

module.exports = {
    NetvoteProvider: async (network)=>{
        if(!networkMap[network]) {
            delete require.cache[require.resolve('./netvote-eth.js')];
            const provider = require("./netvote-eth.js")
            networkMap[network] = provider;
        }
        // refresh with dynamodb data (in case gas price changed)
        await networkMap[network].Init(network);
        return networkMap[network];
    }
}
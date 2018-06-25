const tally = require("@netvote/elections-tally");
const ethUrl = process.env.ETH_URL;


exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));

    try {
        let version = event.version ? event.version : 15;
        let address = event.address;
        let txId = event.txId;

        if(!address){
            throw new Error("must specify address in event")
        }
        if(!txId){
            throw new Error("must specify txId in event")
        }

        let result = await tally.tallyTxVote({
            electionAddress: address,
            txId: txId,
            provider: ethUrl,
            version: version
        })
        callback(null, JSON.stringify(result))
        
    } catch (e) {
        console.error(e);
        callback(e, "error")
    }
};

const tally = require("@netvote/elections-tally");
const networks = require("./eth-networks.js");
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });

exports.handler = iopipe(async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;

    if(event.ping) {
        callback(null, "ok")
        return;
    }
    try {
        let version = event.version ? event.version : 15;
        let address = event.address;
        let txId = event.txId;
        let nv = await networks.NetvoteProvider(event.network);

        if(!address){
            throw new Error("must specify address in event")
        }
        if(!txId){
            throw new Error("must specify txId in event")
        }

        let result = await tally.tallyTxVote({
            electionAddress: address,
            txId: txId,
            provider: nv.ethUrl(),
            version: version
        })
        callback(null, JSON.stringify(result))
        
    } catch (e) {
        console.error(e);
        callback(e, "error")
    }
});

const tally = require("@netvote/elections-tally");
const networks = require("./eth-networks.js");
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const database = require("./netvote-data.js")

exports.handler = iopipe(async (event, context, callback) => {
    console.log(event);
    context.callbackWaitsForEmptyEventLoop = false;

    if(event.ping) {
        callback(null, "ok")
        return;
    }
    try {
        let election = await database.getElection(event.electionId);
        let version = election.version;
        let address = election.address;
        let txId = event.txId;
        let nv = await networks.NetvoteProvider(election.network);
        context.iopipe.label(event.electionId);
        context.iopipe.label(election.network);

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

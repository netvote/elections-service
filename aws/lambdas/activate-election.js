const firebaseUpdater = require("./firebase-updater.js");
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");
const database = require("./netvote-data.js")

const activateElection = async(nv, addr, ElectionPhaseable) => {
    const nonce = await nv.Nonce();
    return ElectionPhaseable.at(addr).activate({nonce: nonce, from: nv.gatewayAddress()})
};

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
        let nv = await networks.NetvoteProvider(election.network);
        context.iopipe.label(event.electionId);
        context.iopipe.label(election.network);
        const ElectionPhaseable = await nv.ElectionPhaseable(version);
        const tx = await activateElection(nv, election.address, ElectionPhaseable);
        console.log("activated election: "+election.address)
        await database.setElectionStatus(event.electionId, "voting");
        await firebaseUpdater.updateDeployedElection(event.electionId, {
            status: "voting",
        });

        await database.setJobSuccess(event.jobId, {
            tx: tx.transactionHash
        })

        await firebaseUpdater.updateStatus(event.callback, {
            tx: tx.tx,
            status: "complete"
        }, true);
        callback(null, "ok")
    }catch(e){
        console.error("error while transacting: ", e);
        await database.setJobError(event.jobId, e.message);
        await firebaseUpdater.updateStatus(event.callback, {
            status: "error"
        });
        callback(e, "ok")
    }
});

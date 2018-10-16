const firebaseUpdater = require("./firebase-updater.js");
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");
const database = require("./netvote-data.js")

const closeElection = async(nv, addr, ElectionPhaseable) => {
    const nonce = await nv.Nonce();
    return ElectionPhaseable.at(addr).close({nonce: nonce, from: nv.gatewayAddress()})
};

const postEncryptionKey = async(nv, addr, key, BaseElection) => {
    const nonce = await nv.Nonce();
    return BaseElection.at(addr).setPrivateKey(key, {nonce: nonce, from: nv.gatewayAddress()})
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
        const BaseElection = await nv.BaseElection(version);
        let statusObj = {}

        // close election
        let tx = await closeElection(nv, election.address, ElectionPhaseable);
        statusObj.tx = tx.tx;
        console.log("closed election: "+election.address)

        // clear voter key
        await database.clearVoterKey(event.electionId);

        // reveal encryption key
        if(!election.resultsAvailable){
            let plainTextKey = await database.getDecryptedKey(event.electionId, "encryption")
            console.log("retrieved encryption key: "+event.electionId)

            let revealTx = await postEncryptionKey(nv, election.address, plainTextKey, BaseElection);
            console.log("encryption key posted: "+event.electionId)

            statusObj.revealTx = revealTx.tx;
            await database.setResultsAvailable(event.electionId, true);
            console.log("set results available: "+event.electionId)
        }
        await database.setElectionStatus(event.electionId, "closed");
        await firebaseUpdater.updateDeployedElection(event.electionId, {
            status: "closed",
            resultsAvailable: true
        });

        await database.setJobSuccess(event.jobId, statusObj)

        statusObj.status = "complete"
        console.log(statusObj);
        await firebaseUpdater.updateStatus(event.callback, statusObj, true);

        await database.asyncLambda("election-export", { electionId: event.electionId })

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

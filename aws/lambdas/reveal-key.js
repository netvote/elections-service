const firebaseUpdater = require("./firebase-updater.js");
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");
const database = require("./netvote-data.js")


const postEncryptionKey = async(nv, addr, key, BaseElection) => {
    const nonce = await nv.Nonce();
    return BaseElection.at(addr).setPrivateKey(key, {nonce: nonce, from: nv.gatewayAddress()})
};

exports.handler = iopipe(async (event, context, callback) => {
    console.log(event);
    context.callbackWaitsForEmptyEventLoop = false;

    try {
        let election = await database.getElection(event.electionId);
        let version = election.version;
        const nv = await networks.NetvoteProvider(election.network);
        const BaseElection = await nv.BaseElection(version);

        // at no point can encryption key be known before vote key is deleted
        await database.clearVoterKey(event.electionId);
        let plainTextKey = await database.getDecryptedKey(event.electionId, "encryption")
    
        const tx = await postEncryptionKey(nv, election.address, plainTextKey, BaseElection);
        context.iopipe.label(event.electionId);
        context.iopipe.label(election.network);
        await firebaseUpdater.updateDeployedElection(event.electionId, {
            resultsAvailable: true
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

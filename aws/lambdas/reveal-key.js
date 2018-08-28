const firebaseUpdater = require("./firebase-updater.js");

const networks = require("./eth-networks.js");

const postEncryptionKey = async(nv, addr, key, BaseElection) => {
    const nonce = await nv.Nonce();
    return BaseElection.at(addr).setPrivateKey(key, {nonce: nonce, from: nv.gatewayAddress()})
};

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;

    try {
        let version = event.version ? event.version : 15;
        const nv = await networks.NetvoteProvider(event.network);
        const BaseElection = await nv.BaseElection(version);
        const tx = await postEncryptionKey(nv, event.address, event.key, BaseElection);
        await firebaseUpdater.updateDeployedElection(event.electionId, {
            resultsAvailable: true
        });
        await firebaseUpdater.updateStatus(event.callback, {
            tx: tx.tx,
            status: "complete"
        }, true);
        callback(null, "ok")
    }catch(e){
        console.error("error while transacting: ", e);
        await firebaseUpdater.updateStatus(event.callback, {
            status: "error"
        });
        callback(e, "ok")
    }
};

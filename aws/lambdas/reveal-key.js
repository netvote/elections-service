const firebaseUpdater = require("./firebase-updater.js");

const nv = require("./netvote-eth.js");
const nonceCounter = require("./nonce-counter.js");

const postEncryptionKey = async(addr, key, BaseElection) => {
    const nonce = await nonceCounter.getNonce(process.env.NETWORK);
    return BaseElection.at(addr).setPrivateKey(key, {nonce: nonce, from: nv.gatewayAddress()})
};

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;

    try {
        let version = event.version ? event.version : 15;
        const BaseElection = await nv.BaseElection(version);
        const tx = await postEncryptionKey(event.address, event.key, BaseElection);
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

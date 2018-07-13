const firebaseUpdater = require("./firebase-updater.js");
const nonceCounter = require("./nonce-counter.js");

const nv = require("./netvote-eth.js");

const activateElection = async(addr, ElectionPhaseable) => {
    const nonce = await nonceCounter.getNonce(process.env.NETWORK);
    return ElectionPhaseable.at(addr).activate({nonce: nonce, from: nv.gatewayAddress()})
};

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;
    if(event.ping) {
        callback(null, "ok")
        return;
    }
    try {
        let version = event.version ? event.version : 15;
        const ElectionPhaseable = await nv.ElectionPhaseable(version);
        const tx = await activateElection(event.address, ElectionPhaseable);
        console.log("activated election: "+event.address)
        await firebaseUpdater.updateDeployedElection(event.electionId, {
            status: "voting",
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

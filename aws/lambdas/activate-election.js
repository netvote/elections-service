const firebaseUpdater = require("./firebase-updater.js");
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");

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
        let version = event.version ? event.version : 15;
        let nv = await networks.NetvoteProvider(event.network);
        context.iopipe.label(event.electionId);
        context.iopipe.label(event.network);
        const ElectionPhaseable = await nv.ElectionPhaseable(version);
        const tx = await activateElection(nv, event.address, ElectionPhaseable);
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
});

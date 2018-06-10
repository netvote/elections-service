const firebaseUpdater = require("./firebase-updater.js");

const nv = require("./netvote-eth.js");
const netvoteContracts = nv.contracts();

const BaseElection = netvoteContracts.BaseElection;

const postEncryptionKey = async(addr, key, nonce) => {
    return BaseElection.at(addr).setPrivateKey(key, {nonce: nonce, from: nv.gatewayAddress()})
};

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));

    try {
        const tx = await postEncryptionKey(event.address, event.key, event.nonce);
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

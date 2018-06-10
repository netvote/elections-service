const firebaseUpdater = require("./firebase-updater.js");

const nv = require("./netvote-eth.js");
const netvoteContracts = nv.contracts();

const BasePool = netvoteContracts.BasePool;

const votedAlready = async (addr, voteId) => {
    console.log("calling votedAlready for addr: "+addr+", voteId: "+voteId)
    let res = await BasePool.at(addr).votes(voteId);
    return res !== '';
};

const castVote = async(voteObj) => {
    console.log("casting vote from "+nv.gatewayAddress())
    let tx = await BasePool.at(voteObj.address).castVote(voteObj.voteId, voteObj.encryptedVote, voteObj.passphrase, voteObj.tokenId, {nonce: voteObj.nonce, from: nv.gatewayAddress()})
    console.log("completed casting vote")
    return tx;
};

const updateVote = async(voteObj) => {
    console.log("updating vote from "+nv.gatewayAddress())
    return await BasePool.at(voteObj.address).updateVote(voteObj.voteId, voteObj.encryptedVote, voteObj.passphrase, voteObj.tokenId, {nonce: voteObj.nonce, from: nv.gatewayAddress()})
    console.log("completed updating vote")
};

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));

    try {
        let update = await votedAlready(event.vote.address, event.vote.voteId);
        console.log("updated already: "+update);
        const ethTransaction = (update) ? updateVote : castVote;
        const tx = await ethTransaction(event.vote);
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

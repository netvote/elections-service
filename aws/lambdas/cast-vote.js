const firebaseUpdater = require("./firebase-updater.js");
const nonceCounter = require("./nonce-counter.js");
// instantiate the iopipe library
var iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const nv = require("./netvote-eth.js");


const votedAlready = async (addr, voteId, BasePool) => {
    console.log("calling votedAlready for addr: "+addr+", voteId: "+voteId)
    let res = await BasePool.at(addr).votes(voteId);
    return res !== '';
};

const castVote = async(voteObj, BasePool) => {
    console.log("casting vote from "+nv.gatewayAddress())
    const nonce = await nonceCounter.getNonce(process.env.NETWORK);
    let tx = await BasePool.at(voteObj.address).castVote(voteObj.voteId, voteObj.encryptedVote, voteObj.passphrase, voteObj.tokenId, {nonce: nonce, from: nv.gatewayAddress()})
    console.log("completed casting vote")
    return tx;
};

const updateVote = async(voteObj, BasePool) => {
    console.log("updating vote from "+nv.gatewayAddress())
    const nonce = await nonceCounter.getNonce(process.env.NETWORK);
    let tx = await BasePool.at(voteObj.address).updateVote(voteObj.voteId, voteObj.encryptedVote, voteObj.passphrase, voteObj.tokenId, {nonce: nonce, from: nv.gatewayAddress()})
    console.log("completed updating vote")
    return tx;
};

exports.handler = iopipe(async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;
    try {
        let version = event.vote.version ? event.vote.version : 15;
        let BasePool = await nv.BasePool(version);
        let update = await votedAlready(event.vote.address, event.vote.voteId, BasePool);
        const ethTransaction = (update) ? updateVote : castVote;
        const tx = await ethTransaction(event.vote, BasePool);
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

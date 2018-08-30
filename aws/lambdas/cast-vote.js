const firebaseUpdater = require("./firebase-updater.js");
// instantiate the iopipe library
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");



const votedAlready = async (addr, voteId, BasePool) => {
    console.log("calling votedAlready for addr: "+addr+", voteId: "+voteId)
    let res = await BasePool.at(addr).votes(voteId);
    return res !== '';
};

const castVote = async(nv, voteObj, BasePool, version) => {
    console.log("casting vote from "+nv.gatewayAddress())
    const nonce = await nv.Nonce();
    let tx;
    if(version > 21){
        if(voteObj.proof){
            tx = await BasePool.at(voteObj.address).castVoteWithProof(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, voteObj.proof, {nonce: nonce, from: nv.gatewayAddress()})
        } else {
            tx = await BasePool.at(voteObj.address).castVote(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, {nonce: nonce, from: nv.gatewayAddress()})
        }
    } else {
        //OLD ELECTIONS
        tx = await BasePool.at(voteObj.address).castVote(voteObj.voteId, voteObj.encryptedVote, "none", voteObj.tokenId, {nonce: nonce, from: nv.gatewayAddress()})
    }
    console.log("completed casting vote")
    return tx;
};

const updateVote = async(nv, voteObj, BasePool, version) => {
    console.log("updating vote from "+nv.gatewayAddress())
    const nonce = await nv.Nonce();
    let tx;
    if(version > 21){
        if(voteObj.proof){
            tx = await BasePool.at(voteObj.address).updateVoteWithProof(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, voteObj.proof, {nonce: nonce, from: nv.gatewayAddress()})
        } else {
            tx = await BasePool.at(voteObj.address).updateVote(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, {nonce: nonce, from: nv.gatewayAddress()})
        }
    } else{
        tx = await BasePool.at(voteObj.address).updateVote(voteObj.voteId, voteObj.encryptedVote, "none", voteObj.tokenId, {nonce: nonce, from: nv.gatewayAddress()})
    }
    console.log("completed updating vote")
    return tx;
};

exports.handler = iopipe(async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;
    try {
        let version = event.vote.version ? event.vote.version : 15;
        let nv = await networks.NetvoteProvider(event.network);
        let BasePool = await nv.BasePool(version);
        let update = await votedAlready(event.vote.address, event.vote.voteId, BasePool);

        const ethTransaction = (update) ? updateVote : castVote;
        let voteType = (update) ? "revote" : "vote"

        context.iopipe.label(event.vote.address);
        context.iopipe.label(event.network);
        context.iopipe.label(voteType);

        const tx = await ethTransaction(nv, event.vote, BasePool, version);
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

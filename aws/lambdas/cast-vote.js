const firebaseUpdater = require("./firebase-updater.js");
// instantiate the iopipe library
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");
const AWS = require("aws-sdk");
const crypto = require('crypto');

const docClient = new AWS.DynamoDB.DocumentClient()

const votedAlready = async (addr, voteId, BasePool) => {
    console.log("calling votedAlready for addr: "+addr+", voteId: "+voteId)
    let res = await BasePool.at(addr).votes(voteId);
    return res !== '';
};

const castVote = async(nv, voteObj, BasePool) => {
    console.log("casting vote from "+nv.gatewayAddress())
    const nonce = await nv.Nonce();
    let tx;
    if(voteObj.proof){
        tx = await BasePool.at(voteObj.address).castVoteWithProof(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, voteObj.proof, {nonce: nonce, from: nv.gatewayAddress()})
    } else {
        tx = await BasePool.at(voteObj.address).castVote(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, {nonce: nonce, from: nv.gatewayAddress()})
    }
    console.log("completed casting vote")
    return tx;
};

const updateVote = async(nv, voteObj, BasePool) => {
    console.log("updating vote from "+nv.gatewayAddress())
    const nonce = await nv.Nonce();
    let tx;
    if(voteObj.proof){
        tx = await BasePool.at(voteObj.address).updateVoteWithProof(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, voteObj.proof, {nonce: nonce, from: nv.gatewayAddress()})
    } else {
        tx = await BasePool.at(voteObj.address).updateVote(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, {nonce: nonce, from: nv.gatewayAddress()})
    }
    console.log("completed updating vote")
    return tx;
};

const updateVoteStatus = async(electionId, voteId, status, txId) => {
    let params = {
        TableName:"votes",
        Key:{
            "electionId": electionId,
            "voteId": voteId
        },
        UpdateExpression: "set txStatus=:sts, txId=:tx",
        ExpressionAttributeValues:{
            ":sts": status,
            ":tx": txId
        },
        ReturnValues:"UPDATED_NEW"
    };
    await docClient.update(params).promise();
}

const insertVote = async(event) => {
    let md5sum = crypto.createHash('md5');
    md5sum.update(`${event.vote.voteId}:${event.vote.encryptedVote}:${event.vote.tokenId}`);
    let voteId = md5sum.digest('hex');
    let params = {
        TableName: "votes",
        Item: {
            "electionId": event.electionId,
            "voteId": voteId,
            "event": event,
            "txTimestamp": new Date().getTime(),
            "txStatus": "pending"
        }
    }
    await docClient.put(params).promise();
    return voteId;
}

exports.handler = iopipe(async (event, context, callback) => {
    console.log(event);
    context.callbackWaitsForEmptyEventLoop = false;
    let voteId;
    try {
        voteId = await insertVote(event);
        console.log({electionId: event.electionId, voteId: voteId})
        let version = event.vote.version ? event.vote.version : 15;
        let nv = await networks.NetvoteProvider(event.network);
        let BasePool = await nv.BasePool(version);
        let update = await votedAlready(event.vote.address, event.vote.voteId, BasePool);

        const ethTransaction = (update) ? updateVote : castVote;
        let voteType = (update) ? "revote" : "vote"

        context.iopipe.label(voteId);
        context.iopipe.label(event.electionId);
        context.iopipe.label(event.network);
        context.iopipe.label(voteType);

        const tx = await ethTransaction(nv, event.vote, BasePool);
        await updateVoteStatus(event.electionId, voteId, "complete", tx.tx);
        await firebaseUpdater.updateStatus(event.callback, {
            tx: tx.tx,
            status: "complete"
        }, true);
        callback(null, "ok")
    }catch(e){
        console.error("error while transacting: ", e);
        if(voteId){
            await updateVoteStatus(event.electionId, voteId, "error", "none");
        }
        await firebaseUpdater.updateStatus(event.callback, {
            status: "error",
            error: e.message || "no message"
        });
        context.iopipe.label("error");
        callback(null, "ok")
    }
});

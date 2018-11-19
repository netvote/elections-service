const firebaseUpdater = require("./firebase-updater.js");
// instantiate the iopipe library
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");
const AWS = require("aws-sdk");
const crypto = require('crypto');
const database = require('./netvote-data.js')

const docClient = new AWS.DynamoDB.DocumentClient()

const votedAlready = async (addr, voteId, BasePool) => {
    console.log("calling votedAlready for addr: "+addr+", voteId: "+voteId)
    let res = await BasePool.at(addr).votes(voteId);
    return res !== '';
};

const castVote = async(nv, address, voteObj, BasePool) => {
    console.log({message: "casting vote", address: address, vote: voteObj});
    const nonce = await nv.Nonce();
    let tx;
    if(voteObj.proof){
        tx = await BasePool.at(address).castVoteWithProof(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, voteObj.proof, {nonce: nonce, from: nv.gatewayAddress()})
    } else {
        tx = await BasePool.at(address).castVote(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, {nonce: nonce, from: nv.gatewayAddress()})
    }
    console.log("completed casting vote")
    return tx;
};

const updateVote = async(nv, address, voteObj, BasePool) => {
    console.log({message: "updating vote", address: address, vote: voteObj});
    const nonce = await nv.Nonce();
    let tx;
    if(voteObj.proof){
        tx = await BasePool.at(address).updateVoteWithProof(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, voteObj.proof, {nonce: nonce, from: nv.gatewayAddress()})
    } else {
        tx = await BasePool.at(address).updateVote(voteObj.voteId, voteObj.encryptedVote, voteObj.tokenId, {nonce: nonce, from: nv.gatewayAddress()})
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

const getVoteId = async(event) => {
    let md5sum = crypto.createHash('md5');
    md5sum.update(`${event.vote.voteId}:${event.vote.tokenId}`);
    return md5sum.digest('hex');
}

const insertVote = async(voteId, event, election, voteType) => {
    let now = new Date();
    let payload = {
        "electionId": event.electionId,
        "voteId": voteId,
        "voterId": event.vote.voteId,
        "owner": election.owner,
        "event": event,
        "voteType": voteType,
        "txTimestamp": now.getTime(),
        "mode": election.mode,
        "txStatus": "pending"
    };

    if(election.mode === "TEST") {
        payload["ttlTimestamp"] = Math.floor((new Date().getTime() + 1000*60*60*24*30)/1000);
    }

    let params = {
        TableName: "votes",
        Item: payload
    }
    await docClient.put(params).promise();
}

exports.handler = iopipe(async (event, context, callback) => {
    console.log(event);
    context.callbackWaitsForEmptyEventLoop = false;
    let voteId;
    let electionId;
    try {
        electionId = event.electionId;
        let election = await database.getElection(electionId);
        let voteId = await getVoteId(event);

        console.log({electionId: electionId, voteId: voteId})

        let version = election.version;
        let nv = await networks.NetvoteProvider(election.network);
        let BasePool = await nv.BasePool(version);
        let update = await votedAlready(election.address, event.vote.voteId, BasePool);

        let voteType = (update) ? "revote" : "vote"
        context.iopipe.label(voteType);

        await insertVote(voteId, event, election, voteType);

        context.iopipe.label(electionId);
        context.iopipe.label(election.network);
        context.iopipe.label(voteId);

        if(update && !election.props.allowUpdates) {
            context.iopipe.label("duplicate-error");
            await updateVoteStatus(electionId, voteId, "duplicate", "none");
            await firebaseUpdater.updateStatus(event.callback, {
                status: "duplicate",
                error: "This voter has already voted.  Updates not allowed."
            });
            callback(null, "duplicate")
            return;
        }

        const ethTransaction = (update) ? updateVote : castVote;

        const tx = await ethTransaction(nv, election.address, event.vote, BasePool);
        await updateVoteStatus(electionId, voteId, "complete", tx.tx);

        await database.setJobSuccess(event.jobId, {
            tx: tx.tx
        })

        await firebaseUpdater.updateStatus(event.callback, {
            tx: tx.tx,
            status: "complete"
        }, true);
        callback(null, "ok")
    }catch(e){
        console.error("error while transacting: ", e);
        if(voteId){
            await updateVoteStatus(electionId, voteId, "error", "none");
        }

        await database.setJobError(event.jobId, {
            error: e.message || "no message"
        })

        await firebaseUpdater.updateStatus(event.callback, {
            status: "error",
            error: e.message || "no message"
        });
        context.iopipe.label("error");

        // not going to retry - will be examined manually
        callback(null, "error")
    }
});

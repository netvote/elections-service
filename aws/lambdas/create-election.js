const AWS = require("aws-sdk");
const kmsClient = new AWS.KMS();

const firebaseUpdater = require("./firebase-updater.js");
const crypto = require('crypto');
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const uuid = require('uuid/v4')
const networks = require("./eth-networks.js");
const database = require("./netvote-data.js")

const VOTE_LIMIT = process.env.VOTE_LIMIT || "10000";
const ENCRYPT_KEY_ARN = "arn:aws:kms:us-east-1:891335278704:key/994f296e-ce2c-4f2b-8cef-48d16644af09";

const toHmac = (value, key) => {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(value);
    return hmac.digest('hex');
};

const generateHashKey = async(collection, id) =>{
    let secret = uuid();
    const encryptionCtx = {"id": id,"type": collection}
    let encrypted = await kmsEncrypt(encryptionCtx, secret);
    let key = toHmac(id, process.env.STORAGE_HASH_SECRET);
    await firebaseUpdater.createDoc(collection, key, {
        secret: {
            stringValue: encrypted
        },
        encrypted: {
            booleanValue: true
        }
    })
    return secret;
}

const kmsEncrypt = async (ctx, plaintext) => {
    const params = { EncryptionContext:ctx, KeyId: ENCRYPT_KEY_ARN, Plaintext: plaintext };
    const result = await kmsClient.encrypt(params).promise()
    return result.CiphertextBlob.toString("base64");
}

const addDeployedElections = async(electionId, addr, election, version, network) => {
    const status = (election.autoActivate) ? "voting" : "building";

    return firebaseUpdater.createDoc("deployedElections", electionId, {
        network: {
            stringValue: network
        },
        status: {
            stringValue: status
        },
        address: {
            stringValue: addr
        },
        allowUpdates: {
            booleanValue: election.allowUpdates
        },
        requireProof: {
            booleanValue: election.requireProof
        },
        metadataLocation: {
            stringValue: election.metadataLocation
        },
        version: {
            integerValue: `${version}`
        },
        resultsAvailable: {
            booleanValue: election.isPublic
        },
        uid: {
            stringValue: election.uid
        },
        demo: {
            booleanValue: election.isDemo
        },
        closeAfter: {
            integerValue: `${election.closeAfter}`
        }
    })
}

const transferVoteAllowance = async (nv, vc, address) => {
    let nonce = await nv.Nonce();
    let web3 = await nv.web3();
    await vc.transfer(address, web3.utils.toWei(VOTE_LIMIT, 'ether'), {nonce: nonce, from: nv.gatewayAddress()})
    console.log(`transfered ${VOTE_LIMIT} vote token to election: ${address}`)
}

const postPrivateKey = async (nv, electionId, address, isPublic) => {
    let encryptionKey = await generateHashKey("encryptionKeys", electionId)
    if (isPublic) {
        let nonce = await nv.Nonce();
        await BasicElection.at(address).setPrivateKey(encryptionKey, {nonce: nonce, from: nv.gatewayAddress()})
        console.log("released private key: "+address)
    }
}

const addElectionToAllowance = async(nv, vc, address) => {
    let nonce = await nv.Nonce();
    await vc.addElection(address, {nonce: nonce, from: nv.gatewayAddress()})
    console.log("added address to vote contract for event subscription")
}

const createElection = async(electionId, election, network, user) => {
    let nv = await networks.NetvoteProvider(network);
    let version = nv.version();
    let VA = await nv.Vote(version)
    let VoteContract = await VA.deployed();
    let web3 = nv.web3();
    let gatewayAddress = nv.gatewayAddress();

    BasicElection = await nv.BasicElection(version);

    let nonce = await nv.Nonce();
    let el = await BasicElection.new(
        web3.utils.sha3(election.uid),
        VoteContract.address,
        gatewayAddress,
        election.allowUpdates,
        gatewayAddress,
        election.metadataLocation,
        gatewayAddress,
        election.autoActivate,
        {from: gatewayAddress, nonce: nonce})
    
    console.log("created election: "+el.address+", id="+electionId);

    await generateHashKey("hashSecrets", electionId)

    let setupTasks = []
    setupTasks.push(transferVoteAllowance(nv, VoteContract, el.address))
    setupTasks.push(postPrivateKey(nv, electionId, el.address, election.isPublic))
    setupTasks.push(addElectionToAllowance(nv, VoteContract, el.address));
    
    await Promise.all(setupTasks);

    let obj = {
        "electionId": electionId,
        "owner": election.uid,
        "props": election,
        "txId": el.transactionHash,
        "network": network,
        "version": version,
        "address": el.address,
        "electionStatus": (election.autoActivate) ? "voting" : "building"
    }

    if(user){
        obj.company = user.company;
    }

    await database.addElection(obj)

    await addDeployedElections(electionId, el.address, election, version, network);
    return el;
}

exports.handler = iopipe(async (event, context, callback) => {
    console.log(event);
    if(event.ping) {
        context.callbackWaitsForEmptyEventLoop = false;
        callback(null, "ok")
        return;
    }
    try {
        let electionId = uuid();
        const tx = await createElection(electionId, event.election, event.network, event.user);

        context.iopipe.label(electionId);
        context.iopipe.label(event.network);

        let result = {
            tx: tx.transactionHash,
            electionId: electionId,
            status: "complete",
            address: electionId
        };

        //aws gateway API
        await database.setJobSuccess(event.jobId, {
            address: tx.address,
            electionId: electionId,
            tx: tx.transactionHash
        })

        //firebase API
        await firebaseUpdater.updateStatus(event.callback, result, true);

        console.log("completed successfully")
        context.callbackWaitsForEmptyEventLoop = false;
        callback(null, "ok")
    }catch(e){
        console.error("error while transacting: ", e);
        await firebaseUpdater.updateStatus(event.callback, {
            status: "error"
        });
        console.log("error, but dropping to avoid replay")
        context.callbackWaitsForEmptyEventLoop = false;
        callback(null, "ok")
    }
});

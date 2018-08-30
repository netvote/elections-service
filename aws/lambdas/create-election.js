const firebaseUpdater = require("./firebase-updater.js");
const crypto = require('crypto');
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const uuid = require('uuid/v4')
const networks = require("./eth-networks.js");

const VOTE_LIMIT = process.env.VOTE_LIMIT || "10000";

const toHmac = (value, key) => {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(value);
    return hmac.digest('hex');
};

const generateHashKey = async(collection, id) =>{
    let secret = uuid();
    let key = toHmac(id, process.env.STORAGE_HASH_SECRET);
    await firebaseUpdater.createDoc(collection, key, {
        secret: {
            stringValue: secret
        }
    })
    return secret;
}

const addDeployedElections = async(electionId, addr, metadataLocation, uid, version, isPublic, autoActivate, isDemo, requireProof, network) => {
    const status = (autoActivate) ? "voting" : "building";

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
        requireProof: {
            booleanValue: requireProof
        },
        metadataLocation: {
            stringValue: metadataLocation
        },
        version: {
            integerValue: `${version}`
        },
        resultsAvailable: {
            booleanValue: isPublic
        },
        uid: {
            stringValue: uid
        },
        demo: {
            booleanValue: isDemo
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

const createElection = async(electionId, election, network, version) => {
    let nv = await networks.NetvoteProvider(network);

    let VA = await nv.Vote(version)
    let VoteContract = await VA.deployed();

    let web3 = nv.web3();
    let gatewayAddress = nv.gatewayAddress();
    version = (version) ? version : 15;
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

    await addDeployedElections(electionId, el.address, election.metadataLocation, election.uid, version, election.isPublic, election.autoActivate, election.isDemo, election.requireProof, network);
    return el;
}

exports.handler = iopipe(async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    if(event.ping) {
        context.callbackWaitsForEmptyEventLoop = false;
        callback(null, "ok")
        return;
    }
    try {
        let electionId = uuid();
        const tx = await createElection(electionId, event.election, event.network, event.version);
        await firebaseUpdater.updateStatus(event.callback, {
            tx: tx.transactionHash,
            electionId: electionId,
            status: "complete",
            address: electionId
        }, true);
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

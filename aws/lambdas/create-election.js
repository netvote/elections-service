const firebaseUpdater = require("./firebase-updater.js");
const crypto = require('crypto');
const uuid = require('uuid/v4')
const nonceCounter = require("./nonce-counter.js");

const nv = require("./netvote-eth.js");
const web3 = nv.web3();

const ETH_NETWORK = nv.network();

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

//TODO: remove this
const addDemoElection = async(addr) =>{
    return firebaseUpdater.createDoc("demoElections", addr, {
        enabled: {
            booleanValue: true
        }
    })
}

const addDeployedElections = async(electionId, addr, metadataLocation, uid, version, isPublic, autoActivate) =>{
    const status = (autoActivate) ? "voting" : "building";

    return firebaseUpdater.createDoc("deployedElections", electionId, {
        network: {
            stringValue: ETH_NETWORK
        },
        status: {
            stringValue: status
        },
        address: {
            stringValue: addr
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
            booleanValue: true
        }
    })
}

const createElection = async(electionId, election, version) => {
    let gatewayAddress = nv.gatewayAddress();
    version = (version) ? version : 15;
    BasicElection = await nv.BasicElection(version);
    VoteContract = await nv.deployedVoteContract(version);

    let nonce = await nonceCounter.getNonce(process.env.NETWORK);
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

    nonce = await nonceCounter.getNonce(process.env.NETWORK);
    await VoteContract.transfer(el.address, web3.utils.toWei("1000", 'ether'), {nonce: nonce, from: nv.gatewayAddress()})
    console.log("transfered 1000 vote token to election: "+el.address)

    let encryptionKey = await generateHashKey("encryptionKeys", electionId)
    if (election.isPublic) {
        nonce = await nonceCounter.getNonce(process.env.NETWORK);
        await BasicElection.at(el.address).setPrivateKey(encryptionKey, {nonce: nonce, from: nv.gatewayAddress()})
        console.log("released private key: "+el.address)
    }

    nonce = await nonceCounter.getNonce(process.env.NETWORK);
    await VoteContract.addElection(el.address, {nonce: nonce, from: nv.gatewayAddress()})
    console.log("added address to vote contract for event subscription")

    await addDeployedElections(electionId, el.address, election.metadataLocation, election.uid, version, election.isPublic, election.autoActivate);
    return el;
}

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));
    context.callbackWaitsForEmptyEventLoop = false;

    try {
        let electionId = uuid();
        const tx = await createElection(electionId, event.election, event.version);
        await firebaseUpdater.updateStatus(event.callback, {
            tx: tx.transactionHash,
            status: "complete",
            address: electionId
        }, true);
        console.log("completed successfully")
        callback(null, "ok")
    }catch(e){
        console.error("error while transacting: ", e);
        await firebaseUpdater.updateStatus(event.callback, {
            status: "error"
        });
        console.log("error, but dropping to avoid replay")
        callback(null, "ok")
    }
};

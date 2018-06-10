const firebaseUpdater = require("./firebase-updater.js");
const crypto = require('crypto');
const uuid = require('uuid/v4')

const nv = require("./netvote-eth.js");
const web3 = nv.web3();
const netvoteContracts = nv.contracts();

const BasicElection = netvoteContracts.BasicElection;
const Vote = netvoteContracts.Vote;

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

const createElection = async(election, nonces) => {
    let gatewayAddress = nv.gatewayAddress();
    let voteAddress = "0xd3f848815c4a70b103757cf519111cfdc85b4cfc"; //TODO: avoid hardcoding
    let el = await BasicElection.new(
        web3.utils.sha3(election.uid),
        voteAddress,
        gatewayAddress,
        election.allowUpdates,
        gatewayAddress,
        election.metadataLocation,
        gatewayAddress,
        election.autoActivate,
        {from: gatewayAddress, nonce: nonces[0]})

    let hashSecret = generateHashKey("hashSecrets", el.address)
    Vote.at(voteAddress).transfer(el.address, web3.utils.toWei("1000", 'ether'), {nonce: nonces[1], from: nv.gatewayAddress()})

    if(election.isPublic){
        let encryptionKey = await generateHashKey("encryptionKeys", el.address)
        BasicElection.at(el.address).setPrivateKey(encryptionKey, {nonce: nonces[2], from: nv.gatewayAddress()})
    } else{
        generateHashKey("encryptionKeys", el.address)
    }
    addDemoElection(el.address);
    return el;
}

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));

    try {
        const tx = await createElection(event.election, event.nonces);
        await firebaseUpdater.updateStatus(event.callback, {
            tx: tx.transactionHash,
            status: "complete",
            address: tx.address
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

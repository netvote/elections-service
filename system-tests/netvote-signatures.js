const ursa = require("ursa");
const protobuf = require("protobufjs");
const IPFS = require('ipfs-mini');
const uuid = require('uuid/v4');

let Vote;

let IPFS_CFG = [{
        host: "ipfs.infura.io",
        protocol: 'https'
    },{
        host: "ipfs.netvote.io",
        port: 8443,
        protocol: 'https'
    }
]

const saveToIPFS = async (data) => {
    let retries = 2;
    for(let i=0; i<retries; i++){
        for(let u = 0; u<IPFS_CFG.length; u++){
            try{
                let ipfs = new IPFS(IPFS_CFG[u]);
                return await await saveToIPFSUnsafe(ipfs, data);
            } catch (e) {
                console.warn("warning, cannot save to ipfs...trying again");
            }
        }
    }
    throw new Error("All attempts failed trying to access ipfs: "+location)
}

const saveToIPFSUnsafe = (ipfs, data) => {
    return new Promise((resolve, reject) => {
        ipfs.add(JSON.stringify(data), (err, result) => {
            if(err){
                    reject(err)
            }else{
                    resolve(result)
            }
        });
    })
}

const initProto = async () => {
    if(!Vote){
        let root = await protobuf.load("../functions/vote.proto");
        Vote = root.lookupType("netvote.Vote");
    }
}

const validateProof = async (voteBase64, proofObj) => {
    if(!proofObj.signature){
        throw new Error("signature is not specified in IPFS proof")
    }
    if(!proofObj.publicKey){
        throw new Error("publicKey is not specified in IPFS proof")
    }
    const pub = ursa.createPublicKey(proofObj.publicKey, 'base64');    
    return pub.hashAndVerify('md5', new Buffer(voteBase64), proofObj.signature, "base64");
}

const signVote = async (voteBase64) => {
    let keyPair = ursa.generatePrivateKey();
    let pub = keyPair.toPublicPem('base64');
    let data = new Buffer(voteBase64);
    let sig = keyPair.hashAndSign('md5', data).toString("base64");
    let obj = {
        signature: sig,
        publicKey: pub
    }
    return await saveToIPFS(obj);
}

const encodeVote = async (payload, signatures) => {
    await initProto();

    let errMsg = Vote.verify(payload);
    if (errMsg) {
        throw Error(errMsg);
    }

    // prevent populating unnecessary fields
    const newVote = {
        ballotVotes: payload.ballotVotes,
    }
    if(signatures){
        newVote.signatureSeed = uuid();
    }

    let vote = Vote.create(newVote);
    let buff = await Vote.encode(vote).finish();
    return buff.toString("base64")
};

module.exports = {
    signVote: signVote,
    encodeVote: encodeVote,
    validateProof: validateProof,
    saveToIPFS: saveToIPFS
}

const ursa = require("ursa");
const protobuf = require("protobufjs");
const IPFS = require('ipfs-mini');
const uuid = require('uuid/v4');

let Vote;

const ipfs = new IPFS({ host: 'ipfs.infura.io', protocol: 'https' });

const saveToIPFS = (data) => {
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
    encodeVote: encodeVote
}

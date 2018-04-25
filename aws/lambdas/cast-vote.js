const google = require('googleapis');
const rp = require('request-promise');

const HDWalletProvider = require("truffle-hdwallet-provider");
const contract = require('truffle-contract');
const Web3 = require("web3");

const web3Provider = new HDWalletProvider(process.env.MNEMONIC, process.env.ETH_URL);
const web3 = new Web3(web3Provider);
web3.eth.defaultAccount = web3Provider.getAddress();
const web3Defaults = {
    from: web3Provider.getAddress(),
    chainId: parseInt(process.env.CHAIN_ID),
    gas: parseInt(process.env.GAS),
    gasPrice: parseInt(process.env.GAS_PRICE)
};

const BasePool = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasePool.json'));
BasePool.setProvider(web3Provider);
BasePool.defaults(web3Defaults);

const updateMask = "updateMask.fieldPaths=status&updateMask.fieldPaths=completeTime&updateMask.fieldPaths=tx";

const castVote = async(voteObj) => {
    console.log("castVote address = "+web3Provider.getAddress());
    return BasePool.at(voteObj.address).castVote(voteObj.voteId, voteObj.encryptedVote, voteObj.passphrase, voteObj.tokenId, {nonce: voteObj.nonce, from: web3Provider.getAddress()})
};

const updateVote = async(voteObj) => {
    console.log("updateVote address = "+web3Provider.getAddress());
    return BasePool.at(voteObj.address).updateVote(voteObj.voteId, voteObj.encryptedVote, voteObj.passphrase, voteObj.tokenId, {nonce: voteObj.nonce, from: web3Provider.getAddress()})
};

const updateStatus = async(doc, status, txId) => {
    if(!doc){
        console.log("skipping updateStatus, no callback specified");
	return;
    }
    const key = require('./key.json');
    const jwtClient = new google.google.auth.JWT({
        email: key.client_email,
        key: key.private_key,
        scopes: ['https://www.googleapis.com/auth/datastore']
    });

    let credential = await jwtClient.authorize();

    let options = {
        method: 'PATCH',
        uri: 'https://firestore.googleapis.com/v1beta1/projects/netvote1/databases/(default)/documents/'+doc+"?"+updateMask,
        body: {
            fields: {
                status: {
                    stringValue: status
                },
                tx: {
                    stringValue: txId
                },
                completeTime: {
                    integerValue: new Date().getTime()
                }
            }
        },
        headers: {
            Authorization: "Bearer "+credential.access_token
        },
        json: true
    };

    try{
        await rp(options);
    }catch(e){
        console.error("error while posting callback, ignoring", e)
    }
};

exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));

    try {
        const ethTransaction = (event.vote.update) ? updateVote : castVote;
        const tx = await ethTransaction(event.vote);
        await updateStatus(event.callback, "complete", tx.tx);
        callback(null, "ok")
    }catch(e){
        console.error("error while transacting: ", e);
        await updateStatus(event.callback, "error", "");
        callback(e, "ok")
    }
};

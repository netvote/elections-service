const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp(functions.config().firebase);
const cookieParser = require('cookie-parser');
const express = require('express');
const cors = require('cors');

let crypto;
let nJwt;

const COLLECTION_HASH_SECRETS = "hashSecrets";
const COLLECTION_VOTER_IDS = "voterIds";
const COLLECTION_ENCRYPTION_KEYS = "encryptionKeys";
const COLLECTION_VOTE_TX = "voteTransaction";
const COLLECTION_ENCRYPTION_TX = "postEncryptionTx";

const ENCRYPT_ALGORITHM = "aes-256-cbc";

//CONFIG
const mnemonic = functions.config().netvote.ropsten.admin.mnemonic;
const apiUrl = functions.config().netvote.ropsten.apiurl;

// for hmac-ing reg key for storage
const regKeySecret = functions.config().netvote.ropsten.voterkeysecret;

// for signing JWT
const voteTokenSecret = functions.config().netvote.ropsten.votetokensecret;

// for hmac-ing voterId
const voterIdHmacSecret = functions.config().netvote.ropsten.voteridhashsecret;

// for hmac-ing stored secrets
const storageHashSecret = functions.config().netvote.ropsten.storagehashsecret;

let uuid;

let HDWalletProvider;
let contract;
let Web3;

let KeyRevealerElection;
let revealerProvider;
let revealerWeb3;

let GatewayElection;
let gatewayProvider;
let gatewayWeb3;

const initUuid = () => {
    if(!uuid) {
        uuid = require('uuid/v4');
    }
};

const initJwt = () => {
    if(!nJwt) {
        nJwt = require('njwt');
    }
};

const initCrypto = () => {
    if(!crypto){
        crypto = require('crypto');
    }
};

const initEth = () => {
    if(!HDWalletProvider) {
        HDWalletProvider = require("truffle-hdwallet-provider");
        contract = require('truffle-contract');
        Web3 = require("web3");
    }
}

const initGateway = () => {
    if(!GatewayElection){
        initEth();
        GatewayElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasicElection.json'));
        gatewayProvider = new HDWalletProvider(mnemonic, apiUrl);
        GatewayElection.setProvider(gatewayProvider);
        gatewayWeb3 = new Web3(gatewayProvider);
        gatewayWeb3.eth.defaultAccount = gatewayProvider.getAddress();
        GatewayElection.defaults({
            from: gatewayProvider.getAddress(),
            chainId: 3,
            gas: 4512388,
            gasPrice: 1000000000000
        });
    }
};

const initRevealer = () => {
    if(!KeyRevealerElection){
        initEth();
        KeyRevealerElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasicElection.json'));
        revealerProvider = new HDWalletProvider(mnemonic, apiUrl);
        KeyRevealerElection.setProvider(revealerProvider);
        revealerWeb3 = new Web3(revealerProvider);
        revealerWeb3.eth.defaultAccount = revealerProvider.getAddress();
        KeyRevealerElection.defaults({
            from: revealerProvider.getAddress(),
            chainId: 3,
            gas: 4512388,
            gasPrice: 1000000000000
        });
    }
};


const sendError = (res, code, txt) => {
    res.status(code).send({"status":"error", "text": txt});
};

const unauthorized = (res) => {
    sendError(res, 401, "Unauthorized");
};

const forbidden = (res) => {
    sendError(res, 403, "Forbidden");
};


// adds auth header to req.token for easy retrieval
const authHeaderDecorator = (req, res, next) => {
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        req.token = req.headers.authorization.split('Bearer ')[1];
        return next();
    }
    unauthorized(res);
};

// from https://github.com/firebase/functions-samples/blob/master/authorized-https-endpoint/functions/index.js
const validateFirebaseIdToken = (req, res, next) => {
    if ((!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) &&
        !req.cookies.__session) {
        console.error('No Firebase ID token was passed as a Bearer token in the Authorization header.',
            'Make sure you authorize your request by providing the following HTTP header:',
            'Authorization: Bearer <Firebase ID Token>',
            'or by passing a "__session" cookie.');
        //TODO: remove, this is just testing
        req.user = {
            uid: "test123"
        };
        return next();
        //unauthorized(res);
    }

    let idToken;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        idToken = req.headers.authorization.split('Bearer ')[1];
    } else {
        idToken = req.cookies.__session;
    }
    admin.auth().verifyIdToken(idToken).then(decodedIdToken => {
        req.user = decodedIdToken;
        next();
    }).catch(error => {
        console.error('Error while verifying Firebase ID token:', error);
        unauthorized(res);
    });
};

const electionOwnerCheck = (req, res, next) => {
    uidOwnsElection(req.user.uid, req.body.address).then((match)=>{
        if(match){
            return next();
        }
        forbidden(res);
    }).catch((e)=>{
        console.error(e);
        forbidden(res);
    });
};

const removeHashKey = (electionId, collection) => {
    let db = admin.firestore();
    const electionHmac = toHmac(electionId, storageHashSecret);
    return db.collection(collection).doc(electionHmac).delete();
};

const submitEncryptTx = (address, key) => {
    let db = admin.firestore();
    return db.collection(COLLECTION_ENCRYPTION_TX).add({
        address: address,
        key: key
    });
};

const submitVoteTx = (address, voteId, encryptedVote) => {
    let db = admin.firestore();
    return db.collection(COLLECTION_VOTE_TX).add({
        address: address,
        voteId: voteId,
        encryptedVote: encryptedVote
    });
};

const getHashKey = (electionId, collection) => {
    initUuid();
    return new Promise(function (resolve, reject) {
        let db = admin.firestore();
        const electionHmac = toHmac(electionId, storageHashSecret);
        db.collection(collection).doc(electionHmac).get().then((doc)=>{
            if(doc.exists){
                resolve(doc.data().secret);
            }else{
                const secret = uuid();
                db.collection(collection).doc(electionHmac).set({
                    secret: secret
                }).then(() => {
                    resolve(secret);
                })
            }
        })
    });
}

const generateKeys = (uid, electionId, count) => {
    initUuid();
    return new Promise(function (resolve, reject) {
        let db = admin.firestore();
        let batch = db.batch();
        try {
            let keys = [];
            for (let i = 0; i < count; i++) {
                const key = uuid();
                keys.push(key);
                const hmacHex = calculateRegKey(electionId, key);
                let ref = db.collection(COLLECTION_VOTER_IDS).doc(hmacHex);
                batch.set(ref, {createdBy: uid, pool: electionId});
            }
            batch.commit().then(()=>{
                resolve(keys);
            });
        }catch(e){
            reject(e);
        }
    });
};

const calculateRegKey = (electionId, key) => {
    return toHmac(electionId + ":" + key, regKeySecret);
};

const hmacVoterId = (voterId) => {
    return toHmac(voterId, voterIdHmacSecret);
};

const toHmac = (value, key) => {
    initCrypto();
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(value);
    return hmac.digest('hex');
};

const uidOwnsElection = (uid, electionId) => {
    initGateway();
    return new Promise(function (resolve, reject) {
        GatewayElection.at(electionId).createdBy().then((createdBy) => {
            resolve(createdBy === uid);
        });
    });
};

const voterIdCheck = (req, res, next) => {
    let key = req.token;
    let address = req.body.address;
    let hmac = calculateRegKey(address, key);
    let db = admin.firestore();
    db.collection(COLLECTION_VOTER_IDS).doc(hmac).get().then((doc)=>{
        if(doc.exists && doc.data().pool === address){
            return next();
        }
        unauthorized(res);
    }).catch((e)=>{
        sendError(res, 500, e.message);
    });
};

const voterTokenCheck = (req, res, next) => {
    initJwt();
    nJwt.verify(req.token, voteTokenSecret,function(err,verifiedJwt){
        if(err){
            unauthorized(res);
        }else{
            req.voter = verifiedJwt.body.sub;
            req.election = verifiedJwt.body.scope;
            next();
        }
    });
};

const createVoterJwt = (electionId, voterId) => {
    initJwt();
    let claims = {
        iss: "https://netvote.io/",
        sub: hmacVoterId(electionId+":"+voterId),
        scope: electionId
    };
    let jwt = nJwt.create(claims,voteTokenSecret);
    jwt.setExpiration(new Date().getTime() + (60*60*1000));
    return jwt.compact();
};

const encrypt = (text, electionId) => {
    initCrypto();
    return new Promise(function (resolve, reject) {
        getHashKey(electionId, COLLECTION_ENCRYPTION_KEYS).then((encryptionKey) => {
            let cipher = crypto.createCipher(ENCRYPT_ALGORITHM, encryptionKey);
            let encrypted = cipher.update(text, "utf8", "base64");
            encrypted += cipher.final("base64");
            resolve(encrypted);
        });
    });
};


// ADMIN APIs
const adminApp = express();
adminApp.use(cors());
adminApp.use(cookieParser());
adminApp.use(validateFirebaseIdToken);
adminApp.use(electionOwnerCheck);
adminApp.post('/keys', (req, res) => {
    if(!req.body.address || !req.body.count){
        sendError(res, 400, "count & address are required");
        return;
    }
    generateKeys(req.user.uid, req.body.address, req.body.count).then((keys) => {
        res.send(keys);
    }).catch((e)=>{
        console.error(e);
        sendError(res, 500, e.message);
    });
});
adminApp.post('/hashsecret', (req, res) => {
    if(!req.body.address){
        sendError(res, 400, "address is required");
        return;
    }
    getHashKey(req.body.address, COLLECTION_HASH_SECRETS).then((s)=>{
        res.send({"status":"ok"});
    }).catch((e)=>{
        console.error(e);
        sendError(res, 500, e.message);
    });
});
adminApp.post('/encryption', (req, res) => {
    initRevealer();
    if(!req.body.address){
        sendError(res, 400, "address is required");
        return;
    }
    getHashKey(req.body.address, COLLECTION_ENCRYPTION_KEYS).then((key)=>{
        return submitEncryptTx(req.body.address, key)
    }).then((ref)=>{
        res.send({txId: ref.id});
    }).catch((e)=>{
        console.error(e);
        sendError(res, 500, e.message);
    });
});

exports.publishEncryption = functions.firestore
    .document(COLLECTION_ENCRYPTION_TX+'/{id}')
    .onCreate(event => {
        initRevealer();
        let data = event.data.data();
        return KeyRevealerElection.at(data.address).setPrivateKey(data.key, {from: revealerProvider.getAddress()}).then((tx)=>{
            return event.data.ref.set({
                tx: tx.tx,
                status: "complete"
            }, {merge: true});
        }).then(()=>{
            return removeHashKey(data.address, COLLECTION_HASH_SECRETS)
        }).catch((e)=>{
            console.error(e);
            return event.data.ref.set({
                status: "error",
                error: e.message
            }, {merge: true});
        });
    });

exports.admin = functions.https.onRequest(adminApp);

// VOTER APIs
const voterApp = express();
voterApp.use(cors());
voterApp.use(authHeaderDecorator);

voterApp.post('/auth', voterIdCheck, (req, res) => {
    res.send({token: createVoterJwt(req.body.address, req.token)});
});

voterApp.post('/cast', voterTokenCheck, (req, res) => {
    initGateway();
    initCrypto();
    let encodedVote = req.body.vote;
    let vote = Buffer.from(encodedVote, 'base64');
    if(!vote){
        sendError(res, 400, "vote is required");
    } else {
        let voteId = "";
        getHashKey(req.election, COLLECTION_HASH_SECRETS).then((secret)=> {
            const voteIdHmac = toHmac(req.election+":"+req.voter, secret);
            voteId = gatewayWeb3.sha3(voteIdHmac);
            return encrypt(vote, req.election);
        }).then((encryptedVote)=>{
            return submitVoteTx(req.election, voteId, encryptedVote);
        }).then((jobRef)=>{
            res.send({txId: jobRef.id});
        }).catch((e) => {
            console.error(e);
            sendError(res, 500, e.message)
        });
    }
});

exports.castVote = functions.firestore
    .document(COLLECTION_VOTE_TX+'/{id}')
    .onCreate(event => {
        initGateway();
        let voteObj = event.data.data();
        console.log("sending tx from "+gatewayProvider.getAddress()+": "+JSON.stringify(voteObj));
        return GatewayElection.at(voteObj.address).castVote(voteObj.voteId, voteObj.encryptedVote, {from: gatewayProvider.getAddress()}).then((tx)=>{
            return event.data.ref.set({
                tx: tx.tx,
                status: "complete"
            }, {merge: true});
        }).catch((e)=>{
            console.error(e);
            return event.data.ref.set({
                status: "error",
                error: e.message
            }, {merge: true});
        });
    });

exports.vote = functions.https.onRequest(voterApp);

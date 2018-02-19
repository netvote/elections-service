const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp(functions.config().firebase);
const cookieParser = require('cookie-parser');
const express = require('express');
const cors = require('cors');

Array.prototype.pushArray = function (arr) {
    this.push.apply(this, arr);
};

let crypto;
let nJwt;

const PHASE_BUILDING = 0;
const PHASE_VOTING = 1;
const PHASE_CLOSED = 2;

const COLLECTION_DEMO_ELECTIONS = "demoElections";

const COLLECTION_HASH_SECRETS = "hashSecrets";
const COLLECTION_VOTER_IDS = "voterIds";
const COLLECTION_ENCRYPTION_KEYS = "encryptionKeys";
const COLLECTION_VOTE_TX = "transactionCastVote";
const COLLECTION_UPDATE_VOTE_TX = "transactionUpdateVote";
const COLLECTION_ENCRYPTION_TX = "transactionPublishKey";
const COLLECTION_CREATE_ELECTION_TX = "transactionCreateElection";
const COLLECTION_ACTIVATE_ELECTION_TX = "transactionActivateElection";
const COLLECTION_CLOSE_ELECTION_TX = "transactionCloseElection";
const COLLECTION_ADMIN_GAS_TX = "transactionAdminGas";

const ENCRYPT_ALGORITHM = "aes-256-cbc";


// SECRETS CONFIG

// for hmac-ing reg key for storage
const regKeySecret = functions.config().netvote.secret.voterkey;

// for signing JWT
const voteTokenSecret = functions.config().netvote.secret.votetoken;

// for hmac-ing voterId
const voterIdHmacSecret = functions.config().netvote.secret.voteridhash;

// for hmac-ing stored secrets
const storageHashSecret = functions.config().netvote.secret.storagehash;

// GATEWAY CONFIG
const DEFAULT_GAS = 4512388;
const DEFAULT_GAS_PRICE = 1000000000000;
const DEFAULT_CHAIN_ID = 3;
const mnemonic = functions.config().netvote.eth.gateway.mnemonic;
const apiUrl = functions.config().netvote.eth.apiurl;
const gas = functions.config().netvote.eth.gas;
const gasPrice = functions.config().netvote.eth.gasprice;
const chainId = functions.config().netvote.eth.chainid;
const allowanceAddress = functions.config().netvote.eth.allowanceaddress;

let uuid;

let HDWalletProvider;
let contract;
let Web3;

// contracts
let ExternalAuthorizable;
let ElectionPhaseable;
let BasicElection;
let BaseElection;
let BasePool;
let BaseBallot;

let web3Provider;
let web3;

let ipfs;

let qr;

const initQr = () => {
    if(!qr) {
        qr = require('qr-image');
    }
}

const initIpfs = () => {
    let IPFS = require('ipfs-mini');
    ipfs = new IPFS({host: 'gateway.ipfs.io', port: 443, protocol: 'https'});
};

const initUuid = () => {
    if (!uuid) {
        uuid = require('uuid/v4');
    }
};

const initJwt = () => {
    if (!nJwt) {
        nJwt = require('njwt');
    }
};

const initCrypto = () => {
    if (!crypto) {
        crypto = require('crypto');
    }
};

const initEth = () => {
    if (!HDWalletProvider) {
        HDWalletProvider = require("truffle-hdwallet-provider");
        contract = require('truffle-contract');
        Web3 = require("web3");
    }
};

const initGateway = () => {
    if (!BasicElection) {
        initEth();
        web3Provider = new HDWalletProvider(mnemonic, apiUrl);
        web3 = new Web3(web3Provider);
        web3.eth.defaultAccount = web3Provider.getAddress();
        const web3Defaults = {
            from: web3Provider.getAddress(),
            chainId: (chainId) ? parseInt(chainId) : DEFAULT_CHAIN_ID,
            gas: (gas) ? parseInt(gas) : DEFAULT_GAS,
            gasPrice: (gasPrice) ? parseInt(gasPrice) : DEFAULT_GAS_PRICE
        };

        ElectionPhaseable = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/ElectionPhaseable.json'));
        ElectionPhaseable.setProvider(web3Provider);
        ElectionPhaseable.defaults(web3Defaults);

        ExternalAuthorizable = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/ExternalAuthorizable.json'));
        ExternalAuthorizable.setProvider(web3Provider);
        ExternalAuthorizable.defaults(web3Defaults);

        BasicElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasicElection.json'));
        BasicElection.setProvider(web3Provider);
        BasicElection.defaults(web3Defaults);

        BaseElection = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BaseElection.json'));
        BaseElection.setProvider(web3Provider);
        BaseElection.defaults(web3Defaults);

        BasePool = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BasePool.json'));
        BasePool.setProvider(web3Provider);
        BasePool.defaults(web3Defaults);

        BaseBallot = contract(require('./node_modules/@netvote/elections-solidity/build/contracts/BaseBallot.json'));
        BaseBallot.setProvider(web3Provider);
        BaseBallot.defaults(web3Defaults);
    }
};


const sendError = (res, code, txt) => {
    res.status(code).send({"status": "error", "text": txt});
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

const ipfsLookup = (metadataLocation) => {
    return new Promise((resolve, reject) => {
        ipfs.catJSON(metadataLocation, (err, metadata) => {
            if (err) {
                console.error(err);
                reject(err);
            }
            let decisions = [];
            metadata.ballotGroups.forEach((bg) => {
                decisions.pushArray(bg.ballotSections);
            });
            resolve({
                decisions: decisions
            });
        });
    })
};

const voteProto = () => {
    let protobuf = require("protobufjs");
    return new Promise((resolve, reject) => {
        protobuf.load("./node_modules/@netvote/elections-solidity/protocol/vote.proto").then((rt) => {
            return rt.lookupType("netvote.Vote");
        }).then((tp) => {
            resolve(tp);
        })
    });
};

const decodeVote = (voteBuff) => {
    return voteProto().then((VoteProto)=>{
        return new Promise((resolve, reject) => {
            let vote;
            try {
                resolve(VoteProto.decode(voteBuff));
            } catch (e) {
                reject("invalid vote structure")
            }
        });
    })
};

const validateVote = (voteBuff, poolAddress) => {
    let vote;
    return new Promise((resolve, reject) => {
        return decodeVote(voteBuff).then((v) => {
            vote = v;
            return BasePool.at(poolAddress).getBallotCount()
        }).then((bc) => {
            const ballotCount = parseInt(bc);
            if (vote.ballotVotes.length !== ballotCount) {
                reject("vote must have "+ballotCount+" ballotVotes, actual=" + vote.ballotVotes.length)
            }
            initIpfs();
            for(let i=0; i<ballotCount; i++){
                let ballotVote = vote.ballotVotes[i];
                // validate this ballot vote
                BasePool.at(poolAddress).getBallot(i).then((ballotAddress)=>{
                    return BaseBallot.at(ballotAddress).metadataLocation()
                }).then((location)=>{
                    return ipfsLookup(location)
                }).then((metadata)=>{

                    if (ballotVote.choices.length !== metadata.decisions.length) {
                        reject("ballotVotes["+i+"] should have " + metadata.decisions.length + " choices but had " + ballotVote.choices.length);
                    }

                    ballotVote.choices.forEach((c, idx) => {
                        if (!c.writeIn) {
                            if (c.selection < 0) {
                                reject("ballotVotes["+i+"] choice["+idx+"] cannot have a selection less than 0")
                            }
                            if (c.selection > (metadata.decisions[idx].ballotItems.length - 1)) {
                                reject("ballotVotes["+i+"] choice["+idx+"] must be between 0 and " + (metadata.decisions[idx].ballotItems.length - 1)+", was="+c.selection)
                            }
                        }else{
                            if(c.writeIn.length > 200){
                                reject("writeIn is limited to 200 characters")
                            }
                        }
                    });
                    resolve(true);
                });
            }
        })
    });
};

const electionOwnerCheck = (req, res, next) => {
    uidAuthorized(req.user.uid, req.body.address).then((match) => {
        if (match) {
            return next();
        }
        forbidden(res);
    }).catch((e) => {
        console.error(e);
        forbidden(res);
    });
};

const removeHashKey = (electionId, collection) => {
    let db = admin.firestore();
    const electionHmac = toHmac(electionId, storageHashSecret);
    return db.collection(collection).doc(electionHmac).delete();
};

const submitEncryptTx = (address, key, deleteHash) => {
    return submitEthTransaction(COLLECTION_ENCRYPTION_TX, {
        address: address,
        key: key,
        deleteHash: deleteHash
    });
};

const submitVoteTx = (address, voteId, encryptedVote, passphrase, pushToken) => {
    return submitEthTransaction(COLLECTION_VOTE_TX, {
        address: address,
        voteId: voteId,
        encryptedVote: encryptedVote,
        passphrase: passphrase,
        pushToken: pushToken
    });
};

const submitUpdateVoteTx = (address, voteId, encryptedVote, passphrase, pushToken) => {
    return submitEthTransaction(COLLECTION_UPDATE_VOTE_TX, {
        address: address,
        voteId: voteId,
        encryptedVote: encryptedVote,
        passphrase: passphrase,
        pushToken: pushToken
    });
};

const submitCreateElectionTx = (allowUpdates, isPublic, metadataLocation, autoActivate, uid) => {
    return submitEthTransaction(COLLECTION_CREATE_ELECTION_TX, {
        allowUpdates: allowUpdates,
        isPublic: isPublic,
        metadataLocation: metadataLocation,
        autoActivate: autoActivate,
        uid: uid
    });
};

const submitEthTransaction = (collection, obj) => {
    let db = admin.firestore();
    return db.collection(collection).add(obj);
};

const isDemoElection = (electionId) => {
    return new Promise(function (resolve, reject) {
        let db = admin.firestore();
        return db.collection(COLLECTION_DEMO_ELECTIONS).doc(electionId).get().then((doc) => {
            if (doc.exists) {
                resolve(doc.data().enabled);
            } else {
                resolve(false);
            }
        });
    })
}

const getHashKey = (electionId, collection) => {
    initUuid();
    return new Promise(function (resolve, reject) {
        let db = admin.firestore();
        const electionHmac = toHmac(electionId, storageHashSecret);
        db.collection(collection).doc(electionHmac).get().then((doc) => {
            if (doc.exists) {
                resolve(doc.data().secret);
            } else {
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
            batch.commit().then(() => {
                resolve(keys);
            });
        } catch (e) {
            reject(e);
        }
    });
};

const votedAlready = (addr, voteId) => {
    return BasePool.at(addr).votes(voteId).then((res)=>{
        return res !== '';
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

const uidAuthorized = (uid, electionId) => {
    initGateway();
    const uidHash = web3.sha3(uid);
    return new Promise(function (resolve, reject) {
        ExternalAuthorizable.at(electionId).isAuthorized(uidHash).then((authorized) => {
            resolve(authorized);
        });
    });
};

const voterIdCheck = (req, res, next) => {
    let key = req.token;
    let address = req.body.address;
    let hmac = calculateRegKey(address, key);
    let db = admin.firestore();
    db.collection(COLLECTION_VOTER_IDS).doc(hmac).get().then((doc) => {
        if (doc.exists && doc.data().pool === address) {
            return next();
        }
        unauthorized(res);
    }).catch((e) => {
        sendError(res, 500, e.message);
    });
};

const voterTokenCheck = (req, res, next) => {
    initJwt();
    nJwt.verify(req.token, voteTokenSecret, function (err, verifiedJwt) {
        if (err) {
            unauthorized(res);
        } else {
            req.voter = verifiedJwt.body.sub;
            req.pool = verifiedJwt.body.scope;
            next();
        }
    });
};

const createVoterJwt = (electionId, voterId) => {
    initJwt();
    let claims = {
        iss: "https://netvote.io/",
        sub: hmacVoterId(electionId + ":" + voterId),
        scope: electionId
    };
    let jwt = nJwt.create(claims, voteTokenSecret);
    jwt.setExpiration(new Date().getTime() + (60 * 60 * 1000));
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

const updatesAreAllowed = (address) => {
    return BasePool.at(address).election((el)=>{

    });
};

const gatewayNonce = () => {
    return new Promise(function (resolve, reject) {
        web3.eth.getTransactionCount(web3Provider.getAddress(), (err, res) => {
            resolve(res);
        });
    });
}

const sendGas = (addr, amount) => {
    return new Promise(function (resolve, reject) {
        gatewayNonce().then((nonce)=>{
            try {
                web3.eth.sendTransaction({
                    to: addr,
                    value: amount,
                    from: web3Provider.getAddress()
                }, (err, res) => {
                    if(!err) {
                        resolve(res)
                    }else{
                        reject(err);
                    }
                })
            }catch(e){
                reject(e);
            }
        })
    });
};

const inPhase = (address, phases) => {
    initGateway();
    return new Promise(function (resolve, reject) {
        ElectionPhaseable.at(address).electionPhase().then((phase) => {
            resolve(phases.indexOf(phase.toNumber()) > -1);
        });
    })
};

// DEMO APIs
const demoApp = express();
demoApp.use(cors());
demoApp.use(cookieParser());
demoApp.get('/qr/election/:address', (req, res) => {
    initQr();
    if (!req.params.address) {
        sendError(res, 400, "address is required");
        return;
    }
    let code = qr.image(req.params.address, { type: 'png' });
    res.setHeader('Content-type', 'image/png');  //sent qr image to client side
    code.pipe(res);
})

demoApp.get('/key/:address', (req, res) => {
    if (!req.params.address) {
        sendError(res, 400, "address is required");
        return;
    }
    return isDemoElection(req.params.address).then((allowed) => {
        if (allowed) {
            generateKeys("demo", req.params.address, 1).then((keys) => {
                res.send({key: keys[0]});
            }).catch((e) => {
                console.error(e);
                sendError(res, 500, e.message);
            });
        }else {
            sendError(res, 403, req.params.address+" is not a demo election");
        }
    });
});

demoApp.get('/qr/key/:address', (req, res) => {
    initQr();
    if (!req.params.address) {
        sendError(res, 400, "address is required");
        return;
    }
    return isDemoElection(req.params.address).then((allowed) => {
        if (allowed) {
            generateKeys("demo", req.params.address, 1).then((keys) => {
                let code = qr.image(keys[0], {type: 'png'});
                res.setHeader('Content-type', 'image/png');  //sent qr image to client side
                code.pipe(res);
            }).catch((e) => {
                console.error(e);
                sendError(res, 500, e.message);
            });
        }else {
            sendError(res, 403, req.params.address+" is not a demo election");
        }
    });
});

exports.demo = functions.https.onRequest(demoApp);


// ADMIN APIs
const adminApp = express();
adminApp.use(cors());
adminApp.use(cookieParser());
adminApp.use(validateFirebaseIdToken);
adminApp.post('/election/keys', electionOwnerCheck, (req, res) => {
    if (!req.body.address || !req.body.count) {
        sendError(res, 400, "count & address are required");
        return;
    }
    if (req.body.count < 1 || reg.body.count > 100) {
        sendError(res, 400, "count must be between 1 and 100");
        return;
    }
    generateKeys(req.user.uid, req.body.address, req.body.count).then((keys) => {
        res.send(keys);
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

adminApp.post('/election/activate', electionOwnerCheck, (req, res) => {
    if (!req.body.address) {
        sendError(res, 400, "address is required");
        return;
    }

    // initializes encryption key
    return getHashKey(req.body.address, COLLECTION_ENCRYPTION_KEYS).then((key)=>{
        return submitEthTransaction(COLLECTION_ACTIVATE_ELECTION_TX,{
            address: req.body.address
        })
    }).then((ref) => {
        res.send({txId: ref.id, collection: COLLECTION_ACTIVATE_ELECTION_TX});
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

adminApp.post('/election/close', electionOwnerCheck, (req, res) => {
    if (!req.body.address) {
        sendError(res, 400, "address is required");
        return;
    }

    return submitEthTransaction(COLLECTION_CLOSE_ELECTION_TX,{
        address: req.body.address
    }).then((ref) => {
        res.send({txId: ref.id, collection: COLLECTION_CLOSE_ELECTION_TX});
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

adminApp.post('/election/encryption', electionOwnerCheck, (req, res) => {
    if (!req.body.address) {
        sendError(res, 400, "address is required");
        return;
    }

    // elections can only add decryption keys IF election is in building or closed states
    return inPhase(req.body.address, [PHASE_BUILDING, PHASE_CLOSED]).then((isValidPhase)=> {
        if (!isValidPhase) {
            sendError(res, 409, "Election must be in Building or Closed state");
            return;
        }
        return getHashKey(req.body.address, COLLECTION_ENCRYPTION_KEYS).then((key) => {
            return submitEncryptTx(req.body.address, key, true);
        }).then((ref) => {
            res.send({txId: ref.id, collection: COLLECTION_ENCRYPTION_TX});
        })
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

adminApp.post('/election', (req, res) => {
    let isPublic = !!(req.body.isPublic);
    let metadataLocation = req.body.metadataLocation;
    let allowUpdates = !!(req.body.allowUpdates);
    let autoActivate = !!(req.body.autoActivate);

    if (!metadataLocation) {
        sendError(res, 400, "metadataLocation is required");
        return;
    }

    return submitCreateElectionTx(allowUpdates, isPublic, metadataLocation, autoActivate, req.user.uid).then((ref) => {
        res.send({txId: ref.id, collection: COLLECTION_CREATE_ELECTION_TX});
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

exports.electionClose = functions.firestore
    .document(COLLECTION_CLOSE_ELECTION_TX + '/{id}')
    .onCreate(event => {
        initGateway();
        let data = event.data.data();
        return gatewayNonce().then((nonce)=>{
            return ElectionPhaseable.at(data.address).close({from: web3Provider.getAddress()})
        }).then((tx) => {
            return event.data.ref.set({
                tx: tx.tx,
                status: "complete"
            }, {merge: true});
        }).catch((e) => {
            console.error(e);
            return event.data.ref.set({
                status: "error",
                error: e.message
            }, {merge: true});
        });
    });

exports.electionActivate = functions.firestore
    .document(COLLECTION_ACTIVATE_ELECTION_TX + '/{id}')
    .onCreate(event => {
        initGateway();
        let data = event.data.data();

        return gatewayNonce().then((nonce)=>{
            return ElectionPhaseable.at(data.address).activate({from: web3Provider.getAddress()})
        }).then((tx) => {
            return event.data.ref.set({
                tx: tx.tx,
                status: "complete"
            }, {merge: true});
        }).catch((e) => {
            console.error(e);
            return event.data.ref.set({
                status: "error",
                error: e.message
            }, {merge: true});
        });
    });

exports.createElection = functions.firestore
    .document(COLLECTION_CREATE_ELECTION_TX + '/{id}')
    .onCreate(event => {
        initGateway();
        let data = event.data.data();

        let gatewayAddress = web3Provider.getAddress();
        let addr = "";
        let tx = "";
        return gatewayNonce().then((nonce)=>{
            return BasicElection.new(
                web3.sha3(data.uid),
                allowanceAddress,
                gatewayAddress,
                data.allowUpdates,
                gatewayAddress,
                data.metadataLocation,
                gatewayAddress,
                data.autoActivate,
                {from: gatewayAddress})
        }).then((el) => {
                addr = el.address;
                tx = el.transactionHash+"";
        }).then(()=>{
            // generate hash key for voters
            return getHashKey(addr, COLLECTION_HASH_SECRETS);
        }).then(()=> {
            return getHashKey(addr, COLLECTION_ENCRYPTION_KEYS)
            // add key if should add key
        }).then((key)=>{
            if (data.isPublic) {
                return submitEncryptTx(addr, key, false);
            } else {
                return null;
            }
        }).then(()=>{
            return event.data.ref.set({
                tx: tx,
                status: "complete",
                address: addr
            }, {merge: true});
        }).catch((e) => {
            console.error(e);
            return event.data.ref.set({
                status: "error",
                error: e.message
            }, {merge: true});
        });
    });

exports.publishEncryption = functions.firestore
    .document(COLLECTION_ENCRYPTION_TX + '/{id}')
    .onCreate(event => {
        initGateway();
        let data = event.data.data();
        return gatewayNonce().then((nonce)=>{
            return BaseElection.at(data.address).setPrivateKey(data.key, {from: web3Provider.getAddress()})
        }).then((tx) => {
            return event.data.ref.set({
                tx: tx.tx,
                status: "complete"
            }, {merge: true});
        }).then(() => {
            return (data.deleteHash) ? removeHashKey(data.address, COLLECTION_HASH_SECRETS) : null
        }).catch((e) => {
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
    let vote;
    let encryptedVote;
    try {
        vote = Buffer.from(encodedVote, 'base64');
    } catch (e) {
        sendError(res, 400, 'must be valid base64 encoding');
        return;
    }
    let update = false;
    if (!vote) {
        sendError(res, 400, "vote is required");
    } else {
        return validateVote(vote, req.pool).then((valid) => {
            let voteId = "";
            const passphrase = req.body.passphrase ? req.body.passphrase : "none";
            getHashKey(req.pool, COLLECTION_HASH_SECRETS).then((secret) => {
                const voteIdHmac = toHmac(req.pool + ":" + req.voter, secret);
                voteId = web3.sha3(voteIdHmac);
                return encrypt(vote, req.pool);
            }).then((encryptedPayload) => {
                encryptedVote = encryptedPayload;
                return votedAlready(req.pool, voteId)
            }).then((votedAlready)=>{
                let pushToken = "";
                if(req.body.pushToken){
                    pushToken = req.body.pushToken;
                }
                if(votedAlready){
                    update = true;
                    return submitUpdateVoteTx(req.pool, voteId, encryptedVote, passphrase, pushToken);
                }else{
                    return submitVoteTx(req.pool, voteId, encryptedVote, passphrase, pushToken);
                }
            }).then((jobRef) => {
                let voteCollection = (update) ? COLLECTION_UPDATE_VOTE_TX : COLLECTION_VOTE_TX;
                res.send({txId: jobRef.id, collection: voteCollection});
            }).catch((e) => {
                console.error(e);
                sendError(res, 500, e.message)
            });
        }).catch((errorText) => {
            sendError(res, 400, errorText);
        });
    }
});

voterApp.post('/update', voterTokenCheck, (req, res) => {
    initGateway();
    initCrypto();
    let encodedVote = req.body.vote;
    let vote;
    try {
        vote = Buffer.from(encodedVote, 'base64');
    } catch (e) {
        sendError(res, 400, 'must be valid base64 encoding');
        return;
    }
    if (!vote) {
        sendError(res, 400, "vote is required");
    } else {
        return updatesAreAllowed(req.pool).then((allowed)=>{
            if(allowed) {
                validateVote(vote, req.pool).then((valid) => {
                    let voteId = "";
                    getHashKey(req.pool, COLLECTION_HASH_SECRETS).then((secret) => {
                        const voteIdHmac = toHmac(req.pool + ":" + req.voter, secret);
                        voteId = web3.sha3(voteIdHmac);
                        return encrypt(vote, req.pool);
                    }).then((encryptedVote) => {
                        let pushToken = "";
                        if(req.body.pushToken){
                            pushToken = req.body.pushToken;
                        }
                        const passphrase = req.body.passphrase ? req.body.passphrase : "none";
                        return submitUpdateVoteTx(req.pool, voteId, encryptedVote, passphrase, pushToken);
                    }).then((jobRef) => {
                        res.send({txId: jobRef.id, collection: COLLECTION_UPDATE_VOTE_TX});
                    }).catch((e) => {
                        console.error(e);
                        sendError(res, 500, e.message)
                    });
                }).catch((errorText) => {
                    sendError(res, 400, errorText);
                });
            }else{
                sendError(res, 403, "This election may not update votes");
            }
        })
    }
});

exports.castVote = functions.firestore
    .document(COLLECTION_VOTE_TX + '/{id}')
    .onCreate(event => {
        initGateway();
        let voteObj = event.data.data();
        return gatewayNonce().then((nonce)=>{
            return BasePool.at(voteObj.address).castVote(voteObj.voteId, voteObj.encryptedVote, voteObj.passphrase, {from: web3Provider.getAddress()})
        }).then((tx) => {
            return event.data.ref.set({
                tx: tx.tx,
                status: "complete",
                voteId: voteObj.voteId
            }, {merge: true});
        }).catch((e) => {
            console.error(e);
            return event.data.ref.set({
                status: "error",
                error: e.message
            }, {merge: true});
        });
    });

exports.updateVote = functions.firestore
    .document(COLLECTION_UPDATE_VOTE_TX + '/{id}')
    .onCreate(event => {
        initGateway();
        let voteObj = event.data.data();
        return gatewayNonce().then((nonce)=>{
            return BasePool.at(voteObj.address).updateVote(voteObj.voteId, voteObj.encryptedVote, voteObj.passphrase, {from: web3Provider.getAddress()})
        }).then((tx) => {
            return event.data.ref.set({
                tx: tx.tx,
                status: "complete",
                voteId: voteObj.voteId
            }, {merge: true});
        }).catch((e) => {
            console.error(e);
            return event.data.ref.set({
                status: "error",
                error: e.message
            }, {merge: true});
        });
    });


const sendNotification = (regToken, text) => {
    return admin.messaging().sendToDevice(regToken, {
        notification: {
            title: 'Vote Accepted',
            body: text,
            icon: 'https://netvote.io/wp-content/uploads/2017/09/cropped-favicon-32x32.png',
        }
    });
};

exports.notifyCastVote = functions.firestore
    .document(COLLECTION_VOTE_TX + '/{id}')
    .onUpdate(event => {
        let jobObj = event.data.data();
        if(jobObj.pushToken){
            if(jobObj.status === "complete"){
                return sendNotification(jobObj.pushToken, jobObj.tx)
            }else if(jobObj.status === "error"){
                return sendNotification(jobObj.pushToken, "error")
            }
        }
    });

exports.notifyUpdateVote = functions.firestore
    .document(COLLECTION_UPDATE_VOTE_TX + '/{id}')
    .onUpdate(event => {
        let jobObj = event.data.data();
        if(jobObj.pushToken){
            if(jobObj.status === "complete"){
                return sendNotification(jobObj.pushToken, jobObj.tx)
            }else if(jobObj.status === "error"){
                return sendNotification(jobObj.pushToken, "error")
            }
        }
    });


exports.vote = functions.https.onRequest(voterApp);

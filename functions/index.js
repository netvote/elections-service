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

const ALLOWANCE_ADDRESS = "0xdd7bd7cc567c025ac49d7892ec9c33a0ca298ca6";

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

let ipfs;

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
    if (!GatewayElection) {
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
    if (!KeyRevealerElection) {
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
        let root = protobuf.load("./node_modules/@netvote/elections-solidity/protocol/vote.proto").then((rt) => {
            return rt.lookupType("netvote.Vote");
        }).then((tp) => {
            resolve(tp);
        })
    });
};

const validateVote = (voteBuff, address) => {
    initIpfs();

    let VoteProto;
    let metaLocation;
    return GatewayElection.at(address).metadataLocation().then((location) => {
        metaLocation = location;
        return voteProto();
    }).then((vp) => {
        VoteProto = vp;
        return ipfsLookup(metaLocation)
    }).then((metadata) => {
        return new Promise((resolve, reject) => {
            let vote;
            try {
                vote = VoteProto.decode(voteBuff);
            } catch (e) {
                reject("invalid vote structure")
            }
            //TODO: support multiple ballots
            if (vote.ballotVotes.length !== 1) {
                reject("vote must have 1 ballotVotes entry, actual=" + vote.ballotVotes.length)
            }

            if (vote.ballotVotes[0].choices.length !== metadata.decisions.length) {
                reject("vote should have " + metadata.decisions.length + " choices but had " + vote.ballotVotes[0].choices.length);
            }

            vote.ballotVotes[0].choices.forEach((c, idx) => {
                if (!c.writeIn) {
                    if (c.selection < 0) {
                        reject("vote cannot have a selection less than 0")
                    }
                    if (c.selection > (metadata.decisions[idx].ballotItems.length - 1)) {
                        reject("vote must be between 0 and " + (metadata.decisions[idx].ballotItems.length - 1))
                    }
                }
            });
            resolve(true);
        })
    })
};


const electionOwnerCheck = (req, res, next) => {
    uidOwnsElection(req.user.uid, req.body.address).then((match) => {
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

const submitVoteTx = (address, voteId, encryptedVote, passphrase) => {
    return submitEthTransaction(COLLECTION_VOTE_TX, {
        address: address,
        voteId: voteId,
        encryptedVote: encryptedVote,
        passphrase: passphrase
    });
};

const submitUpdateVoteTx = (address, voteId, encryptedVote, passphrase) => {
    return submitEthTransaction(COLLECTION_UPDATE_VOTE_TX, {
        address: address,
        voteId: voteId,
        encryptedVote: encryptedVote,
        passphrase: passphrase
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
    return GatewayElection.at(addr).votes(voteId).then((res)=>{
        console.log("res="+res);
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
            req.election = verifiedJwt.body.scope;
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
    initGateway();
    return GatewayElection.at(address).allowVoteUpdates()
};

const gatewayNonce = () => {
    return new Promise(function (resolve, reject) {
        gatewayWeb3.eth.getTransactionCount(gatewayProvider.getAddress(), (err, res) => {
            resolve(res);
        });
    });
}

const revealerNonce = () => {
    return new Promise(function (resolve, reject) {
        revealerWeb3.eth.getTransactionCount(revealerProvider.getAddress(), (err, res) => {
            resolve(res);
        });
    });
};

const sendGas = (addr, amount) => {
    return new Promise(function (resolve, reject) {
        gatewayNonce().then((nonce)=>{
            try {
                gatewayWeb3.eth.sendTransaction({
                    to: addr,
                    value: amount,
                    from: gatewayProvider.getAddress()
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

    return submitEthTransaction(COLLECTION_ACTIVATE_ELECTION_TX,{
        address: req.body.address
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

adminApp.post('/gas', (req, res) => {
    if (!req.body.address) {
        sendError(res, 400, "address is required");
        return;
    }

    return submitEthTransaction(COLLECTION_ADMIN_GAS_TX, {
        address: req.body.address
    }).then((ref) => {
        res.send({txId: ref.id, collection: COLLECTION_ADMIN_GAS_TX});
    }).catch((e) => {
        console.error(e);
        sendError(res, 500, e.message);
    });
});

exports.payAdminGas = functions.firestore
    .document(COLLECTION_ADMIN_GAS_TX + '/{id}')
    .onCreate(event => {
        initGateway();
        let data = event.data.data();
        return sendGas(data.address, gatewayWeb3.toWei(4, "ether")).then((txId) => {
            return event.data.ref.set({
                tx: txId,
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

exports.electionClose = functions.firestore
    .document(COLLECTION_CLOSE_ELECTION_TX + '/{id}')
    .onCreate(event => {
        initGateway();
        let data = event.data.data();
        return gatewayNonce().then((nonce)=>{
            return GatewayElection.at(data.address).close({from: gatewayProvider.getAddress()})
        }).then((tx) => {
            return event.data.ref.set({
                tx: tx.tx,
                status: "complete"
            }, {merge: true});
        }).then(()=>{
            return getHashKey(data.address, COLLECTION_ENCRYPTION_KEYS)
        }).then((key)=>{
            return submitEncryptTx(data.address, key, true)
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
            return GatewayElection.at(data.address).activate({from: gatewayProvider.getAddress()})
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

        let gatewayAddress = gatewayProvider.getAddress();
        let addr = "";
        let tx = "";
        return gatewayNonce().then((nonce)=>{
            return GatewayElection.new(
                data.uid,
                ALLOWANCE_ADDRESS,
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
        }).then(()=>{
            // add key if should add key
            if (data.isPublic) {
                return getHashKey(addr, COLLECTION_ENCRYPTION_KEYS).then((key) => {
                    return submitEncryptTx(addr, key, false);
                })
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
        initRevealer();
        let data = event.data.data();
        return revealerNonce().then((nonce)=>{
            return KeyRevealerElection.at(data.address).setPrivateKey(data.key, {from: revealerProvider.getAddress()})
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
        return validateVote(vote, req.election).then((valid) => {
            let voteId = "";
            const passphrase = req.body.passphrase ? req.body.passphrase : "none";
            getHashKey(req.election, COLLECTION_HASH_SECRETS).then((secret) => {
                const voteIdHmac = toHmac(req.election + ":" + req.voter, secret);
                voteId = gatewayWeb3.sha3(voteIdHmac);
                return encrypt(vote, req.election);
            }).then((encryptedPayload) => {
                encryptedVote = encryptedPayload;
                return votedAlready(req.election, voteId)
            }).then((votedAlready)=>{
                if(votedAlready){
                    update = true;
                    return submitUpdateVoteTx(req.election, voteId, encryptedVote, passphrase);
                }else{
                    return submitVoteTx(req.election, voteId, encryptedVote, passphrase);
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
        return updatesAreAllowed(req.election).then((allowed)=>{
            if(allowed) {
                validateVote(vote, req.election).then((valid) => {
                    let voteId = "";
                    getHashKey(req.election, COLLECTION_HASH_SECRETS).then((secret) => {
                        const voteIdHmac = toHmac(req.election + ":" + req.voter, secret);
                        voteId = gatewayWeb3.sha3(voteIdHmac);
                        return encrypt(vote, req.election);
                    }).then((encryptedVote) => {
                        const passphrase = req.body.passphrase ? req.body.passphrase : "none";
                        return submitUpdateVoteTx(req.election, voteId, encryptedVote, passphrase);
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
            return GatewayElection.at(voteObj.address).castVote(voteObj.voteId, voteObj.encryptedVote, voteObj.passphrase, {from: gatewayProvider.getAddress()})
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
            return GatewayElection.at(voteObj.address).updateVote(voteObj.voteId, voteObj.encryptedVote, voteObj.passphrase, {from: gatewayProvider.getAddress()})
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


exports.vote = functions.https.onRequest(voterApp);

const https = require('https');
const protobuf = require("protobufjs");

const VOTE = ""
let VoteProto;

const initializeParameters = async() => {
    let root = await protobuf.load("./node_modules/@netvote/elections-solidity/protocol/vote.proto");
    VoteProto = root.lookupType("netvote.Vote");
    if(process.argv.length < 3){
        console.error("Eth address (0x...) is required argument");
        process.exit(1);
    }
    const election = process.argv[2];
    let count = 1;
    let pin;
    if(process.argv.length > 3){
        count = parseInt(process.argv[3])
    }
    if(process.argv.length > 4){
        pin = process.argv[4];
    }
    return {
        election: election,
        count: count,
        pin: pin
    }
}

const toEncodedVote = async (payload) => {
    let errMsg = VoteProto.verify(payload);
    if (errMsg) {
        throw "error encoding proto: "+errMsg;
    }
    let res = VoteProto.create(payload);
    let encoded = await VoteProto.encode(res).finish();
    return encoded.toString("base64")
};

const post = async(path, obj, auth) => {
    return new Promise((resolve, reject) => {
        console.log("POST "+path)
        let postData = JSON.stringify(obj);
        let options = {
            hostname: 'netvote1.firebaseapp.com',
            port: 443,
            path: path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': postData.length
            }
        };
        if(auth){
            options.headers["Authorization"] = "Bearer "+auth;
        }
        let req = https.request(options, (res) => {
            res.on('data', (d) => { 
                console.log("response: "+d);
                resolve(JSON.parse(d));
            });
        });

        req.on('error', (e) => {
            reject(e);
        });

        req.write(postData);
        req.end();
    });
}

const generateKeys = async(election, count) => {
    let body = {
        address: election,
        count: count
    }
    return post("/admin/election/keys", body);
}

const getJwt = async(election, key) => {
    let body = {
        address: election
    }
    return post("/vote/auth", body, key)
}

const castVote = async(election, jwt, vote, pin) => {
    let voteBase64 = await toEncodedVote({
        ballotVotes: [
            {
                choices: [
                    {
                        selection: 2
                    },
                    {
                        selection: 1
                    },
                    {
                        selection: 1
                    }
                ]
            }
        ]
    })

    let body = {
        vote: voteBase64
    }

    if(pin){
        body.pin = pin;
    }

    return post("/vote/cast", body, jwt)
}

const castAllVotes = async () => {
    let params = await initializeParameters();
    let keys = await generateKeys(params.election, params.count);
    let votes = []
    for(let i=0; i<keys.length; i++){
        let jwt = await getJwt(params.election, keys[i]);
        votes.push(castVote(params.election, jwt.token, VOTE, params.pin))
    }
    return Promise.all(votes)
}

castAllVotes().then((res)=>{
    console.log("results = %s", JSON.stringify(res))
}).catch((e)=>{
    console.error(e);
});
const AWS = require("aws-sdk");
const docClient = new AWS.DynamoDB.DocumentClient()

let NETWORK;

const rp = require('request-promise-native');
const HDWalletProvider = require("truffle-hdwallet-provider");
const contract = require('truffle-contract');
const Web3 = require("web3");

const contractCache = {}

let web3Provider;
let web3;
let web3Defaults;

const initProvider = () => {
    if(!NETWORK) {
        throw new Error("network not initialized");
    }
    web3Provider = new HDWalletProvider(NETWORK.mnemonic, NETWORK.url);
    web3 = new Web3(web3Provider);
    web3.eth.defaultAccount = web3Provider.getAddress();
    web3Defaults = {
        from: web3Provider.getAddress(),
        chainId: NETWORK.chainId,
        gas: NETWORK.gas
    };
    
    if(NETWORK.gasPrice){
        web3Defaults.gasPrice = NETWORK.gasPrice;
    }
}

const toContractUrl = (name, version) => {
    return `https://s3.amazonaws.com/netvote-election-contracts/${version}/${name}.json`
}

const getAbi = async (name, version) => {
    const url = toContractUrl(name, version);
    if(contractCache[url]) {
        return contractCache[url]
    }
    const c = contract(await rp(url, { json: true }))
    c.setProvider(web3Provider)
    c.defaults(web3Defaults);
    contractCache[url] = c;
    console.log(`loaded ${name}/${version} from S3`)
    return c;
}

const getVoteAbi = (version) => {
    if(version <= 15){
        return getAbi("Vote", version)
    } else{
        //17+ (there is no 16)
        return getAbi("VoteAllowance", version)
    }
}

const getNonce = () => {
    const table = "nonces";
    const expression = "set nonce = nonce + :val"
    return new Promise((resolve, reject) => {
        var params = {
            TableName: table,
            Key:{
                "name": NETWORK.id
            },
            UpdateExpression: expression,
            ExpressionAttributeValues:{
                ":val": 1
            },
            ReturnValues:"UPDATED_NEW"
        };

        docClient.update(params, function(err, data) {
            if (err) {
                console.error("Unable to update item. Error JSON:", JSON.stringify(err, null, 2));
                reject(err);
            } else {
                console.log("UpdateItem succeeded:", JSON.stringify(data, null, 2));
                resolve(data.Attributes.nonce);
            }
        });
    })
}



module.exports = {
    Init: async (network) => {
        let params = {
            TableName: "networks",
            Key:{
                "id": network
            }
        };
        let data = await docClient.get(params).promise();
        NETWORK = data.Item;
        initProvider();
    },
    Nonce: () => {
        return getNonce();
    },
    BasicElection: (version) => {
        return getAbi("BasicElection", version)
    },
    BasePool: (version) => {
        return getAbi("BasePool", version)
    },
    BaseBallot: (version) => {
        return getAbi("BaseBallot", version)
    },
    BaseElection: (version) => {
        return getAbi("BaseElection", version)
    },
    ElectionPhaseable: (version) => {
        return getAbi("ElectionPhaseable", version)
    },
    KeyHolder: (version) => {
        return getAbi("KeyHolder", version)
    },
    Observances: (version) => {
        //only available from v19
        return getAbi("Observances", version)
    },
    Vote: (version) => {
        return getVoteAbi(version)
    },
    Ping: async () =>{
        let vc = await getVoteAbi(22)
        let v = await vc.deployed();
        await v.owner();
    },
    deployedVoteContract: async (version) => {
        console.log("1")
        let vc = await getVoteAbi(version)
        console.log("2")
        try{
            let dep = await vc.deployed();
            console.log("3")
            return dep;
        }catch(e){
            console.error("ERROR:", e)
        }
        console.log("4")
        throw new Error("nope")
    },
    VoteAllowance: (version) => {
        return getAbi("VoteAllowance", version)
    },
    network: () => {
        return process.env.NETWORK || "ropsten"
    },
    gatewayAddress: () => {
        return web3Provider.getAddress();
    },
    web3: () => {
        return web3;
    },
    ethUrl: () => {
        return NETWORK.url;
    }
}
var AWS = require('aws-sdk');
var s3 = new AWS.S3();

const fs = require("fs")
const archiver = require('archiver');


const networks = require("./eth-networks.js");
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const tally = require("@netvote/elections-tally");
const database = require("./netvote-data.js")
const uuid = require("uuid/v4");

const writeVote = async(jobId, voteKey, vote) => {
    return new Promise((resolve, reject)=>{
        fs.writeFile(`/tmp/${jobId}/votes/${voteKey}`, JSON.stringify(vote), function(err) {
            if(err){
                reject(err);
            } else {
                resolve(true);
            }
        });
    })
}

const writeVotesToS3 = async(jobId, electionId) => {
    return new Promise((resolve, reject)=>{

        //zip votes
        let zipPath = `/tmp/${jobId}/votes.zip`
        var output = fs.createWriteStream(zipPath);
        var archive = archiver('zip');

        archive.on('error', function(err){
            reject(err);
        });

        archive.pipe(output);
        archive.directory(`/tmp/${jobId}/votes/`, false)
        archive.finalize();

        output.on('close', function() {
            fs.readFile(zipPath, async function (err, data) {
                if(err){
                    console.error(err);
                    reject(err);
                }
                let key = `${electionId}/votes.zip`
                let obj = data;
                var params = {
                    Bucket : "netvote-public-results",
                    Key : key,
                    Body : obj,
                    ACL: 'public-read'
                }
                await s3.putObject(params).promise();
                resolve(true);
            })
        });
    });
}

exports.handler = iopipe(async (event, context, callback) => {
    console.log(event);
    context.callbackWaitsForEmptyEventLoop = false;
    if(event.ping) {
        callback(null, "ok")
        return;
    }
    try {
        let jobId = uuid();
        fs.mkdirSync(`/tmp/${jobId}`);
        fs.mkdirSync(`/tmp/${jobId}/votes`);

        let election = await database.getElection(event.electionId);
        let version = election.version;
        let validateSignatures = !!(election.props.requireProof);
        let address = election.address;
        let nv = await networks.NetvoteProvider(election.network);
        if(!address){
            throw new Error("must specify address in event")
        }

        let counter = 0;
        context.iopipe.label(event.electionId);
        context.iopipe.label(election.network);
        context.iopipe.label((validateSignatures) ? "signatures" : "no-signatures");
    
        setTimeout(()=>{
            if(counter === 0){
                callback(new Error("timeout while trying to tally"), {message: "timeout trying to tally"})
            }
        }, 5000)

        let res = await tally.tallyElection({
            electionAddress: address,
            version: version,
            provider: nv.ethUrl(),
            validateSignatures: validateSignatures,
            export: true,
            badVoteCallback: async(obj)=>{
                counter++;
                await writeVote(jobId, `bad-vote${counter}.json`, obj)
            },
            resultsUpdateCallback: async (res) => {
                counter++;
                await writeVote(jobId, `vote${counter}.json`, res.vote)
            }
        })

        await writeVotesToS3(jobId, event.electionId)

        callback(null, JSON.stringify(res))
        
    } catch (e){
        console.error("error while tallying: ", e);
        callback(e, "ok")
    }
});

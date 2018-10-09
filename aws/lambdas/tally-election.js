const firebaseUpdater = require("./firebase-updater.js");
const networks = require("./eth-networks.js");
const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const tally = require("@netvote/elections-tally");
const updateEveryNVotes = process.env.UPDATE_EVERY_N_VOTES ? parseInt(process.env.UPDATE_EVERY_N_VOTES) : 100;
const database = require("./netvote-data.js")

exports.handler = iopipe(async (event, context, callback) => {
    console.log(event);
    context.callbackWaitsForEmptyEventLoop = false;
    if(event.ping) {
        callback(null, "ok")
        return;
    }
    try {
        let election = await database.getElection(event.electionId);
        let version = election.version;
        let validateSignatures = !!(election.props.requireProof);
        let address = election.address;
        let nv = await networks.NetvoteProvider(election.network);
        if(!address){
            throw new Error("must specify address in event")
        }

        let counter = 0;
        let badVotes = [];
        context.iopipe.label(event.electionId);
        context.iopipe.label(election.network);
        context.iopipe.label((validateSignatures) ? "signatures" : "no-signatures");
    
        setTimeout(()=>{
            if(counter === 0){
                callback(new Error("timeout while trying to tally"), {message: "timeout trying to tally"})
            }
        }, 5000)

        let result = await tally.tallyElection({
            electionAddress: address,
            version: version,
            provider: nv.ethUrl(),
            validateSignatures: validateSignatures,
            resultsUpdateCallback: async (res) => {
                counter++;
                if(counter % updateEveryNVotes == 0){
                    await firebaseUpdater.updateStatus(event.callback, {
                        status: "tallying",
                        progress: JSON.stringify(res.progress),
                        results: JSON.stringify(res.result)
                    }, true);
                }
            },
            badVoteCallback: async (obj)=>{
                console.warn("BADVOTE:"+JSON.stringify(obj))
                badVotes.push(obj);
                await firebaseUpdater.updateStatus(event.callback, {
                    badVotes: JSON.stringify(badVotes)
                }, true);
            }
        })
    

        console.log("result: "+JSON.stringify(result))

        //aws gateway API
        await database.setJobSuccess(event.jobId, {
            results: result
        })

        await firebaseUpdater.updateStatus(event.callback, {
            status: "complete",
            results: JSON.stringify(result)
        }, true);
        callback(null, "ok")
        
    } catch (e){
        console.error("error while tallying: ", e);
        await firebaseUpdater.updateStatus(event.callback, {
            status: "error"
        });
        callback(e, "ok")
    }
});

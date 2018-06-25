const firebaseUpdater = require("./firebase-updater.js");

const tally = require("@netvote/elections-tally");
const ethUrl = process.env.ETH_URL;
const updateEveryNVotes = process.env.UPDATE_EVERY_N_VOTES ? parseInt(process.env.UPDATE_EVERY_N_VOTES) : 100;


exports.handler = async (event, context, callback) => {
    console.log("event: "+JSON.stringify(event));
    console.log("context: "+JSON.stringify(context));

    try {
        let version = event.version ? event.version : 15;
        let address = event.address;
        if(!address){
            throw new Error("must specify address in event")
        }

        let counter = 0;

        let result = await tally.tallyElection({
            electionAddress: address,
            version: version,
            provider: ethUrl,
            resultsUpdateCallback: async (res) => {
                counter++;
                if(counter % updateEveryNVotes == 0){
                    await firebaseUpdater.updateStatus(event.callback, {
                        status: "tallying",
                        progress: JSON.stringify(res.progress),
                        results: JSON.stringify(res.result)
                    }, true);
                }
            }
        })

        console.log("result: "+JSON.stringify(result))

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
};

const iopipe = require('@iopipe/iopipe')({ token: process.env.IO_PIPE_TOKEN });
const networks = require("./eth-networks.js");
const database = require("./netvote-data.js");

exports.handler = iopipe(async (event, context, callback) => {
    console.log(event);
    context.callbackWaitsForEmptyEventLoop = false;

    const electionId = event.electionId;
    const election = await database.getElection(electionId);
    const votes = await database.getVotes(electionId);
    
    const nv = await networks.NetvoteProvider(election.network);
    const BasePool = await nv.BasePool(election.version);

    let votesByVoterId = {}
    votes["complete"].forEach((vote) => {
        votesByVoterId[vote.voterId] = {
            sentVote: vote.event.vote.encryptedVote,
            sentProof: vote.event.vote.proof
        }
    })

    // audit total number of votes adds up
    let expectedTotal = Object.keys(votesByVoterId).length
    let actualTotal = await BasePool.at(election.address).getVoteCount();
    let totalConfirmed = (expectedTotal === parseInt(actualTotal));
    let totalAudit = {
        totalConfirmed: totalConfirmed,
        sentTotal: expectedTotal,
        chainTotal: parseInt(actualTotal)
    } 

    // report on number of votes by status (error/duplicate/complete)
    let statusCounts = {}
    Object.keys(votes).forEach((status) => {
        statusCounts[status] = votes[status].length;
    })

    let problemVotes = [];

    // check each vote matches the result stored on chain
    Object.keys(votesByVoterId).forEach(async (voteId) => {
        let expectedVote = votesByVoterId[voteId].sentVote;
        let expectedProof = votesByVoterId[voteId].sentProof;
        let actualVote = await BasePool.at(election.address).votes(voteId);
        let actualProof = await BasePool.at(election.address).proofs(voteId);

        //default to blank to align with solidity default
        expectedProof = expectedProof || "";
        votesByVoterId[voteId].chainVote = actualVote;
        votesByVoterId[voteId].chainProof = actualProof;
        votesByVoterId[voteId].voteConfirmed = (expectedVote === actualVote);
        votesByVoterId[voteId].proofConfirmed = (expectedProof === actualProof);
        votesByVoterId[voteId].confirmed == (votesByVoterId[voteId].voteConfirmed && votesByVoterId[voteId].proofConfirmed)
        if(!votesByVoterId[voteId].confirmed){
            problemVotes.push(voteId);
        }
    })

    let result = {
        status: statusCounts,
        totals: totalAudit,
        votes: votesByVoterId,
        problemVotes: problemVotes
    }

    callback(null, result)
    return;
});
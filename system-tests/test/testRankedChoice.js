const assert = require('assert');
const nv = require('../netvote-request');
const nvEncoder = require('../netvote-signatures')

const ballot = {
	"type": "basic",
	"ballotTitle": "Test",
	"ballotLocation": "Not Implemented",
	"ballotDate": null,
	"ballotImage": null,
	"featuredImage": "https://netvote.io/wp-content/uploads/2018/03/roswell-ga.jpg",
	"ballotInformation": "Not Implemented",
	"ballotGroups": [{
		"groupTitle": "RChain Coop Electorate",
		"ballotSections": [{
			"type": "single",
			"sectionTitle": "Board Seat #1",
			"sectionTitleNote": "There is one candidate running for Board Seat #1.<br/>If you <b>do support </b> the candidate for this position, select the <b> For </b> option.<br/>If you <b>do not support</b> the candidate for this position, select the <b> Withhold </b> option.<br/>If you prefer not to vote on this contest, check <b> Abstain </b> below.",
			"ballotItems": [{
				"itemTitle": "Scott Anderson For",
				"itemDescription": "Choice description"
			}, {
				"itemTitle": "Scott Anderson Withhold",
				"itemDescription": "Choice description"
			}]
		}, {
			"type": "single",
			"sectionTitle": "Board Seat #2",
			"sectionTitleNote": "There is one candidate running for Board Seat #2.<br />If you <b>do support</b> the candidate for this position, select the <b>For</b> option.<br />If you <b>do not support</b> the candidate for this position, select the <b>Withhold</b> option.<br />If you prefer not to vote on this contest, check <b>Abstain</b> below.",
			"ballotItems": [{
				"itemTitle": "Shirlee Priestly For",
				"itemDescription": "Choice description"
			}, {
				"itemTitle": "Shirlee Priestly Withhold",
				"itemDescription": "Choice description"
			}]
		}, {
			"type": "ranked",
			"sectionTitle": "Board Seat #3",
			"sectionTitleNote": "There are multiple candidates for Board Seat #3.\r\n                        <br />\r\n                        Rank your candidate choices 1-4 by <b>dragging</b> each candidate box into your preferred position,\r\n                        with the top position being preferred most and the bottom position being preferred least.\r\n                        <br />\r\n                        <b>You must rank all candidates.</b>\r\n                        <br />\r\n                        If you prefer not to vote on this contest, check <b>Abstain</b> below.",
			"ballotItems": [{
				"itemTitle": "Casey Altuva",
				"itemDescription": "Choice description"
			}, {
				"itemTitle": "Erica Chanowski",
				"itemDescription": "Choice description"
			}, {
				"itemTitle": "Frank Hansen",
				"itemDescription": "Choice description"
			}, {
				"itemTitle": "Jose Rodriquez-Martin",
				"itemDescription": "Choice description"
			}]
		}, {
			"type": "ranked",
			"sectionTitle": "Ombudsman Committee",
			"sectionTitleNote": "There are multiple candidates for <b>2 positions</b> on the Ombudsman Committee.\r\n                        <br />\r\n                        Rank your candidate choices 1-3 by <b>dragging</b> each candidate box into your preferred position,\r\n                        with the top position being preferred most and the bottom position being preferred least.\r\n                        <br />\r\n                        <b>You must rank all candidates.</b>\r\n                        <br />\r\n                        If you prefer not to vote on this contest, check <b>Abstain</b> below.",
			"ballotItems": [{
				"itemTitle": "Wong Chen",
				"itemDescription": "Choice description"
			}, {
				"itemTitle": "Kari Martin",
				"itemDescription": "Choice description"
			}, {
				"itemTitle": "Sonal Patel",
				"itemDescription": "Choice description"
			}]
		}, {
			"type": "single",
			"sectionTitle": "Referendum Question #1",
			"sectionTitleNote": "If you support this Bylaw Change, select the <b>For</b> option.\r\n                        <br />\r\n                        If you <b>do not support</b> this Bylaw change, select the <b>Withhold</b> option.\r\n                        <br />\r\n                        For this Bylaw Change to be approved a threshhold of 60% of active members must vote <b>For</b>.\r\n                        <br />\r\n                        If you prefer not to vote on this contest, check <b>Abstain</b> below.",
			"ballotItems": [{
				"itemTitle": "Changes to Article VIII - Section 8.1 For",
				"itemDescription": "Choice description"
			}, {
				"itemTitle": "Changes to Article VIII - Section 8.1 Withhold",
				"itemDescription": "Choice description"
			}]
		}]
	}]
};


const metadataLocation = 'QmQRs8Vr4STtLG9ipeNtm44ciQ4Dc6gYRvB3zAvsVfXdS3';

const VOTE_0 = {
  ballotVotes: [
    {
        choices: [
            {
                selection: 0
            },
            {
                selection: 0
            },
            {
                pointsAllocations: {
                    points: [1,2,3,4]
                }
            },
            {
                pointsAllocations: {
                    points: [1,2,3]
                }
            },
            {
                selection: 1
            }
        ]
    }
  ]
}

const VOTE_1 = {
    ballotVotes: [
      {
          choices: [
              {
                  selection: 0
              },
              {
                  selection: 1
              },
              {
                  pointsAllocations: {
                      points: [3,4,2,1]
                  }
              },
              {
                  pointsAllocations: {
                      points: [2,3,1]
                  }
              },
              {
                  selection: 1
              }
          ]
      }
    ]
  }

const itemName = (decision, index) => {
    return ballot.ballotGroups[0].ballotSections[decision].ballotItems[index].itemTitle;
}


const toVotePayload = async (electionId, voteObj, requireProofs) => {
  let vbase64 = await nvEncoder.encodeVote(voteObj, requireProofs);
  let payload = {
    electionId: electionId,
    vote: vbase64
  }
  if(requireProofs){
    payload.proof =  await nvEncoder.signVote(vbase64);
  }
  return payload;
}


const expectResult = (res, candidate, votes) => {
  assert.equal(res[candidate], votes, `${candidate} should have ${votes} votes`);
}

let TEST_NETWORK = "netvote";

describe(`Ranked Choice Election`, function() {

  let scenarios = [
    {
      'name': 'election with signature verification',
      'isPublic' : false,
      'requireProof': true,
      'metadataLocation': metadataLocation,
      'allowUpdates': false,
      'closeAfter': new Date().getTime(),
      'voteStartTime': new Date().getTime(),
      'voteEndTime': new Date().getTime()+1000000,
      'autoActivate': false,
      'network': TEST_NETWORK
    },
  ]

  scenarios.forEach((options) => {

    describe(options.name, function() {
      let deployedElection;
      let electionId;
      let keys;
      let tokens;
      let txIds = [];

      it('should create election', async () => {
        let res = await nv.CreateElection(options);
        let deployedElection = await nv.GetDeployedElection(res.electionId);
        assert.equal(deployedElection.network, options.network)
        let expectedStatus = options.autoActivate ? 'voting' : 'building'
        assert.equal(deployedElection.status, options.autoActivate ? 'voting' : 'building', `expected ${expectedStatus} status`)
        assert.equal(deployedElection.resultsAvailable, options.isPublic)
        assert.equal(deployedElection.demo, false)
        electionId = res.electionId;
        console.log(`electionId: ${electionId}`)
      });

      if(!options.autoActivate) {
        it('should manually activate election', async()=>{
          await nv.ActivateElection({
            electionId: electionId
          });
          deployedElection = await nv.GetDeployedElection(electionId);
          assert.equal(deployedElection.status, 'voting')
        })
      }

      it('should generate voter keys', async()=>{
        keys = await nv.GenerateVoterKeys({
          electionId: electionId,
          count: 2
        });
        assert.equal(keys.length, 2)
      })

      it('should upload voter key', async()=>{
        let response = await nv.UploadVoterKeys({
          electionId: electionId,
          keys: ["test123"]
        });
        assert.equal(response.count, 1)
        keys.push("test123");
      })

      it('should get three voter tokens', async()=>{
        let payload = { electionId: electionId }

        let token1 = await nv.GetVoterToken(payload, keys[0])
        let token2 = await nv.GetVoterToken(payload, keys[1])
        let token3 = await nv.GetVoterToken(payload, keys[2])

        tokens = [token1, token2, token3]
      })

      it('should check vote before vote', async()=>{
        let payload = { electionId: electionId }

        let check1 = await nv.CheckVote(payload, keys[0]);
        let check2 = await nv.CheckVote(payload, keys[1]);
        let check3 = await nv.CheckVote(payload, keys[2]);

        [check1,check2,check3].forEach((check) => {
          assert.equal(check.voted, false, "should not have voted already");
          assert.equal(check.canVote, true, "should have voted already");
        })
      })

      it('should cast three votes', async()=>{

        // each is different if signing, because signature seed is uuid()
        let payload1 = await toVotePayload(electionId, VOTE_0, options.requireProof);
        let payload2 = await toVotePayload(electionId, VOTE_0, options.requireProof);
        let payload3 = await toVotePayload(electionId, VOTE_1, options.requireProof);

        let tx1 = await nv.CastVote(payload1, tokens[0])
        let tx2 = await nv.CastVote(payload2, tokens[1])
        let tx3 = await nv.CastVote(payload3, tokens[2])

        // save off first for retrieval later
        txIds.push(tx1.tx)

        assert.equal(tx1.status, "complete")
        assert.equal(tx2.status, "complete")
        assert.equal(tx3.status, "complete");
      })

      it('should check vote after vote', async()=>{
        let payload = { electionId: electionId }

        let check1 = await nv.CheckVote(payload, keys[0]);
        let check2 = await nv.CheckVote(payload, keys[1]);
        let check3 = await nv.CheckVote(payload, keys[2]);

        [check1,check2,check3].forEach((check) => {
          assert.equal(check.voted, true, "should have voted already");
          assert.equal(check.canVote, options.allowUpdates, "canVote should equal allowUpdates");
        })
      })

      it('should stop election', async()=>{
        await nv.StopElection({
          electionId: electionId
        });
        deployedElection = await nv.GetDeployedElection(electionId);
        assert.equal(deployedElection.stopped, true)
      })

      it('should get vote transactions', async()=>{
        let tx = await nv.GetVoteTransactions(electionId);
        assert.equal(tx.stats.complete, 3);
      })

      it('should close election', async()=>{
        await nv.CloseElection({
          electionId: electionId
        });
        deployedElection = await nv.GetDeployedElection(electionId);
        assert.equal(deployedElection.status, 'closed')
        assert.equal(deployedElection.resultsAvailable, true)
      })

      it('should tally election correctly', async()=>{
        let deployedElection = await nv.GetDeployedElection(electionId);
        const result = await nv.TallyElection(electionId);
        const ballotTotal = result.ballots[deployedElection.address].totalVotes;
        assert.equal(ballotTotal, 3, "expected 3 votes");
        const ballotResults = result.ballots[deployedElection.address].results['ALL'];

        expectResult(ballotResults[0], itemName(0,0), 3)
        expectResult(ballotResults[0], itemName(0,1), 0)
        expectResult(ballotResults[1], itemName(1,0), 2)
        expectResult(ballotResults[1], itemName(1,1), 1)
        expectResult(ballotResults[2], itemName(2,0), 1.6666666666666667)
        expectResult(ballotResults[2], itemName(2,1), 2.6666666666666665)
        expectResult(ballotResults[2], itemName(2,2), 2.6666666666666665)
        expectResult(ballotResults[2], itemName(2,3), 3)
        expectResult(ballotResults[3], itemName(3,0), 1.3333333333333333)
        expectResult(ballotResults[3], itemName(3,1), 2.3333333333333335)
        expectResult(ballotResults[3], itemName(3,2), 2.3333333333333335)
        expectResult(ballotResults[4], itemName(4,0), 0)
        expectResult(ballotResults[4], itemName(4,1), 3)
      })

    });

  })
});

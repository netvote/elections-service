const assert = require('assert');
const nv = require('../netvote-request');

const metadataLocation = 'QmZaKMumAXXLkHPBV1ZdAVsF4XCUYz1Jp5PY3oEsLrKoy6';
const VOTE_1_1_1 = 'CLlgEgwKAggBCgIIAQoCCAE=';
const VOTE_0_0_0 = 'CLlgEgwKAggACgIIAAoCCAA=';

const expectResult = (res, candidate, votes) => {
  assert.equal(res[candidate], votes, `${candidate} should have ${votes} votes`);
}

["netvote"].forEach((network) => {
  describe(`End to End Election, network=${network}`, function() {

    let tests = [
      {
        'name': 'private election with manual activation',
        'isPublic' : false,
        'metadataLocation': metadataLocation,
        'allowUpdates': true,
        'autoActivate': false,
        'network': network
      },
      {
        'name': 'public election with auto activation',
        'isPublic' : true,
        'metadataLocation': metadataLocation,
        'allowUpdates': true,
        'autoActivate': true,
        'network': network
      },
    ]
  
    tests.forEach((options) => {
  
      describe(options.name, function() {
        let deployedElection;
        let electionId;
        let keys;
        let tokens;
        let txIds = [];
  
        it('should create election', async () => {
          let res = await nv.CreateElection(options);
          let deployedElection = await nv.GetDeployedElection(res.electionId);
          assert.equal(deployedElection.network, network)
          let expectedStatus = options.autoActivate ? 'voting' : 'building'
          assert.equal(deployedElection.status, options.autoActivate ? 'voting' : 'building', `expected ${expectedStatus} status`)
          assert.equal(deployedElection.resultsAvailable, options.isPublic)
          electionId = res.electionId;
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
            count: 3
          });
          assert.equal(keys.length, 3)
        })
  
        it('should get three voter tokens', async()=>{
          let token1 = await nv.GetVoterToken({
            electionId: electionId
          }, keys[0])
          let token2 = await nv.GetVoterToken({
            electionId: electionId
          }, keys[1])
          let token3 = await nv.GetVoterToken({
            electionId: electionId
          }, keys[2])
  
          tokens = [token1, token2, token3]
        })
  
        it('should cast three votes', async()=>{
          let tx1 = await nv.CastVote({
            electionId: electionId,
            vote: VOTE_0_0_0
          }, tokens[0])
          let tx2 = await nv.CastVote({
            electionId: electionId,
            vote: VOTE_1_1_1
          }, tokens[1])
          let tx3 = await nv.CastVote({
            electionId: electionId,
            vote: VOTE_1_1_1
          }, tokens[2])
  
          // save off for retrieval later
          txIds.push(tx1.tx)
          txIds.push(tx2.tx)
          txIds.push(tx3.tx)

          assert.equal(tx1.status, "complete")
          assert.equal(tx2.status, "complete")
          assert.equal(tx3.status, "complete");
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
          const result = await nv.TallyElection(electionId);
          const ballotTotal = result.ballots[deployedElection.address].totalVotes;
          assert.equal(ballotTotal, 3, "expected 3 votes");
          const ballotResults = result.ballots[deployedElection.address].results['ALL'];
          expectResult(ballotResults[0], "John Smith", 1)
          expectResult(ballotResults[0], "Sally Gutierrez", 2)
          expectResult(ballotResults[0], "Tyrone Williams", 0)
          expectResult(ballotResults[1], "Yes", 1)
          expectResult(ballotResults[1], "No", 2)
          expectResult(ballotResults[2], "Doug Hall", 1)
          expectResult(ballotResults[2], "Emily Washington", 2)
        })

        it('should lookup votes correctly', async()=>{
          let res1 = await nv.LookupVote(electionId, txIds[0])
          let ballotResults = res1.ballots[deployedElection.address].results['ALL'];
          expectResult(ballotResults[0], "John Smith", 1)
          expectResult(ballotResults[0], "Sally Gutierrez", 0)
          expectResult(ballotResults[0], "Tyrone Williams", 0)
          expectResult(ballotResults[1], "Yes", 1)
          expectResult(ballotResults[1], "No", 0)
          expectResult(ballotResults[2], "Doug Hall", 1)
          expectResult(ballotResults[2], "Emily Washington", 0)

          let res2 = await nv.LookupVote(electionId, txIds[1])
          ballotResults = res2.ballots[deployedElection.address].results['ALL'];
          expectResult(ballotResults[0], "John Smith", 0)
          expectResult(ballotResults[0], "Sally Gutierrez", 1)
          expectResult(ballotResults[0], "Tyrone Williams", 0)
          expectResult(ballotResults[1], "Yes", 0)
          expectResult(ballotResults[1], "No", 1)
          expectResult(ballotResults[2], "Doug Hall", 0)
          expectResult(ballotResults[2], "Emily Washington", 1)

          let res3 = await nv.LookupVote(electionId, txIds[2])
          ballotResults = res3.ballots[deployedElection.address].results['ALL'];
          expectResult(ballotResults[0], "John Smith", 0)
          expectResult(ballotResults[0], "Sally Gutierrez", 1)
          expectResult(ballotResults[0], "Tyrone Williams", 0)
          expectResult(ballotResults[1], "Yes", 0)
          expectResult(ballotResults[1], "No", 1)
          expectResult(ballotResults[2], "Doug Hall", 0)
          expectResult(ballotResults[2], "Emily Washington", 1)
        })
  
      });
  
    })
  
    
  });
})



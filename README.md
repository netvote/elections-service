# elections-service
Demo API integration for Netvote 

Background
-------------------
As described in the [Netvote White Paper](https://netvote.io/wp-content/uploads/2018/01/Netvote-White-Paper-v6.pdf), accepting a vote involves Authentication, Authorization, and a Vote Gateway.  For large elections (Government or otherwise), Authentication & Authorization steps will involve integrations that will vary per organization.  This project provides a demo-ready Authentication, Authorization, and Vote Gateway built on top of Firebase via a set of APIs.  

Note: This project has not undergone any security audit, and should not be used to manage real elections at this time.

APIs
-------------------

## Vote APIs

### POST /vote/auth

Exchange a registration key for a vote token.  The key is in place of what would normally involve showing one's ID at a polling station.  In this case, it is the Admin's reponsibility to distribute the key safely to voters who may vote.

Note:
- The vote token is currently good for one hour from exchange. 
- Another token can be requested at any time.  (The blockchain prevents duplicate voting)

Header
```
Authorization: Bearer REG-KEY-HERE
```

Body:
```
{
	"address": "0xethereum-address",
	"count": 1
}
```
Returns:
```
{
	"token": "JWT-TOKEN"
}
```

### POST /vote/cast

Casts a vote for the election.  If a vote has already been cast for this voter (baked into JWT key), an update will occur (if election allows updates)

Note:
- This will validate the vote matches the ballot schema of options defined in the metadata.  (same number of options, valid choices)

Header
```
Authorization: Bearer JWT-TOKEN
```
Body:
```
{
	"vote": "base64-of-serialized-proto",
	"passphrase": "any text",
	"pushToken": "abc123"
}
```
- **vote**: (required) this is a BASE64-encoded serialized Vote message from [Vote.proto](https://github.com/netvote/elections-solidity/blob/master/protocol/vote.proto)
- **passphrase**: (optional) allows a voter to identify their vote on the blockchain without decrypting (pre-close)
- **pushToken**: (optional) API will kindly send a push message to voter when vote has been cast

Returns:
```
{"txId":"OBJECT-REFERENCE","collection":"transactionCastVote"}
```
Note: 
- The firebase collection reference can be polled for completion.  (obj.status = complete) 

### POST /vote/update

Casts an UPDATE vote for the election.  This update can only be called if vote has already been cast.

Header
```
Authorization: Bearer JWT-TOKEN
```
Body:
```
{
	"vote": "base64-of-serialized-proto",
	"passphrase": "any text",
	"pushToken": "abc123"
}
```
- **vote**: (required) this is a BASE64-encoded serialized BallotVotes message from [Vote.proto](https://github.com/netvote/elections-solidity/blob/master/protocol/vote.proto)
- **passphrase**: (optional) allows a voter to identify their vote on the blockchain without decrypting (pre-close)
- **pushToken**: (optional) API will kindly send a push message to voter when vote has been cast

Returns:
```
{"txId":"OBJECT-REFERENCE","collection":"transactionCastVote"}
```
Note: 
- The firebase collection reference can be polled for completion.  (obj.status = complete) 

## Admin APIs

Note: these are primarily for demo purposes.  We expect standard elections to be fully-DApp driven.  There may be a case where we support a service-like experience.

### POST /admin/election

Create an election on the ethereum blockchain owned by the current firebase user UID.  Only that user may invoke other election-specific admin APIs.

Body:
```
{
	"autoActivate": true,
	"metadataLocation": "ipfs-address",
	"allowUpdates": true,
	"isPublic": true
}
```
- **autoActivate**: (optional) allow voting immediately
- **metadataLocation**: (required) address of ballot metadata on IPFS
- **allowUpdates**: (optional) allow voters to update their vote after the fact (enforced on chain)
- **isPublic**: (optional) generate and post the encryption key to the ballot immediately so tallying can occur during the election

Returns:
```
{"txId":"DI3emygqJPQqfimpbbBn","collection":"transactionCreateElection"}
```
Note: 
- The firebase collection reference can be polled for completion.  (obj.status = complete) 

### POST /admin/election/keys

Generate registration keys for the election and return.  This will store a one-way HMAC of the key in firebase to be looked up.  

NOTE: the UID must be [authorized](https://github.com/netvote/elections-solidity/blob/master/contracts/auth/ExternalAuthorizable.sol) by the election contract.

Body:
```
{
	"address": "0xethereum-address",
	"count": 1
}
```
- **address**: (required) address of election on ethereum
- **count**: (required) address of ballot metadata on IPFS

Returns:
```
["key1", "key2"...]
```

The response is the only time these keys are visible.  The admin must ensure these are delivered to voters correctly.


### POST /admin/election/activate

If not already activated (via autoActivate), this will allow voting for the election.

NOTE: the UID must be [authorized](https://github.com/netvote/elections-solidity/blob/master/contracts/auth/ExternalAuthorizable.sol) by the election contract.

Body:
```
{
	"address": "0xethereum-address"
}
```
- **address**: (required) address of election on ethereum

### POST /admin/election/close

This will permanently close the election (no more votes allowed).

NOTE: the UID must be [authorized](https://github.com/netvote/elections-solidity/blob/master/contracts/auth/ExternalAuthorizable.sol) by the election contract.

Body:
```
{
	"address": "0xethereum-address"
}
```
- **address**: (required) address of election on ethereum

### POST /admin/election/encryption

This will post the encryption key to the election contract to allow for vote reveal.  

NOTE: 
- the UID must be [authorized](https://github.com/netvote/elections-solidity/blob/master/contracts/auth/ExternalAuthorizable.sol) by the election contract.
- the election must be either closed OR not yet activated 

Body:
```
{
	"address": "0xethereum-address"
}
```
- **address**: (required) address of election on ethereum

Contributing
-------------------

### Contribution Process
1. Fork repo
2. Make desired changes
3. Submit PR (Reference Issue #)
4. Reviewer will review
5. Reviewer Squash + Merges PR

License
-------
All code is released under the <a href='https://www.gnu.org/licenses/gpl-3.0.en.html'>GNU General Public License v3.0</a>.

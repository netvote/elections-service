const IPFS = require('ipfs-mini');

const ipfs = new IPFS({ host: 'ipfs.infura.io', protocol: 'https' });

module.exports = {
    putItem: (payload) => {
        return new Promise((resolve, reject) => {
            ipfs.add(payload, (err, result) => {
                if (err) {
                    reject(err);
                } else{
                    resolve(result);
                }
            });
        })  
    }
}
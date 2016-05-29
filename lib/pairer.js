const crypto = require('crypto')
const db = require('./postgresql_interface')
const certify = require('./certify')

exports.pair = function pair (token, csr, hmac) {
  return db.fetchPairing(token)
  .then(pairingRec => {
    const _hmac = crypto.createHmac('sha256', pairingRec.secret)
    if (hmac !== _hmac.update(csr).final('base64')) throw new Error("HMAC doesn't match")

    return certify.issueMachineCert(csr)
  })
  .then(cert => ({certificate: cert, ca: certify.ca()}))
}

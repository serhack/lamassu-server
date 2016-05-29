const path = require('path')
const crypto = require('crypto')
const pify = require('pify')
const fs = pify(require('fs'))
const forge = require('node-forge')
const pki = forge.pki
const BigNumber = require('bignumber.js')

const CERTS_PATH = path.resolve(__dirname, '..', 'certs')
const CA_SERVER_CERT_PATH = path.resolve(CERTS_PATH, 'ca-server.pem')
const CA_MACHINE_CERT_PATH = path.resolve(CERTS_PATH, 'ca-machine.pem')
const CA_MACHINE_CERT_KEY_PATH = path.resolve(CERTS_PATH, 'ca-machine.key')

exports.issue = function issue (csrPem) {
  const csr = pki.certificationRequestFromPem(csrPem)
  if (!csr.verify()) return Promise.reject(new Error('Invalid CSR'))

  Promise.all([
    fs.readFile(CA_SERVER_CERT_PATH),
    fs.readFile(CA_MACHINE_CERT_PATH),
    fs.readFile(CA_MACHINE_CERT_KEY_PATH)
  ])
  .then(arr => {
    const caServerPem = arr[0]
    const caPem = arr[1]
    const caKeyPem = arr[2]

    const caCert = pki.certificateFromPem(caPem)
    const caKey = pki.privateKeyFromPem(caKeyPem)

    const cert = pki.createCertificate()
    cert.publicKey = csr.publicKey
    const randomHex = '0x' + crypto.randomBytes(16).toString('hex')
    cert.serialNumber = new BigNumber(randomHex).toFixed()
    cert.validity.notBefore = new Date()
    cert.validity.notAfter = new Date()
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)
    cert.setSubject(csr.subject.attributes)
    cert.setIssuer(caCert.subject.attributes)
    cert.sign(caKey, forge.md.sha256.create())
    const certPem = pki.certificateToPem(cert)

    return {certificate: certPem, ca: caServerPem}
  })
}

const fs = require('fs')
const crypto = require('crypto')
const forge = require('node-forge')
const pki = forge.pki
const BigNumber = require('bignumber.js')

var keys = forge.pki.rsa.generateKeyPair(2048)

// create a certification request (CSR)
var csr = forge.pki.createCertificationRequest()
csr.publicKey = keys.publicKey
csr.setSubject([{
  name: 'commonName',
  value: 'example.org'
}, {
  name: 'countryName',
  value: 'US'
}, {
  shortName: 'ST',
  value: 'Virginia'
}, {
  name: 'localityName',
  value: 'Blacksburg'
}, {
  name: 'organizationName',
  value: 'Test'
}, {
  shortName: 'OU',
  value: 'Test'
}])

// sign certification request
csr.sign(keys.privateKey)

// -------------------- Now comes the CA signing

const caPem = fs.readFileSync('ca-cert.pem')
const caKeyPem = fs.readFileSync('ca-cert.key')

const caCert = pki.certificateFromPem(caPem)
const caKey = pki.privateKeyFromPem(caKeyPem)

// generate a keypair and create an X.509v3 certificate
const cert = pki.createCertificate()
cert.publicKey = csr.publicKey
cert.serialNumber = new BigNumber('0x' + crypto.randomBytes(16).toString('hex')).toFixed()
cert.validity.notBefore = new Date()
cert.validity.notAfter = new Date()
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)
cert.setSubject(csr.subject.attributes)
cert.setIssuer(caCert.subject.attributes)

// self-sign certificate
cert.sign(caKey, forge.md.sha256.create())

// convert a Forge certificate to PEM
const pem = pki.certificateToPem(cert)

console.log(pem)

/*

SUCCESS!

$ openssl verify -CAfile ./ca-cert.pem test-cert.pem
test-cert.pem: OK

*/

const forge = require('node-forge')
const fs = require('fs')
const pki = forge.pki

// generate a keypair and create an X.509v3 certificate
const keys = pki.rsa.generateKeyPair(2048)
const cert = pki.createCertificate()
cert.publicKey = keys.publicKey
cert.serialNumber = '01'
cert.validity.notBefore = new Date()
cert.validity.notAfter = new Date()
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)
const attrs = [{
  name: 'commonName',
  value: 'lamassu.is'
}, {
  name: 'countryName',
  value: 'VG'
}, {
  shortName: 'ST',
  value: 'Tortola'
}, {
  name: 'localityName',
  value: 'Road Town'
}, {
  name: 'organizationName',
  value: 'Lamassu'
}]
cert.setSubject(attrs)
cert.setIssuer(attrs)
cert.setExtensions([{
  name: 'basicConstraints',
  cA: true
}, {
  name: 'keyUsage',
  keyCertSign: true,
  digitalSignature: true,
  nonRepudiation: true,
  keyEncipherment: true,
  dataEncipherment: true
}, {
  name: 'extKeyUsage',
  serverAuth: true,
  clientAuth: true,
  codeSigning: true,
  emailProtection: true,
  timeStamping: true
}, {
  name: 'nsCertType',
  client: true,
  server: true,
  email: true,
  objsign: true,
  sslCA: true,
  emailCA: true,
  objCA: true
}])
cert.sign(keys.privateKey)
const pem = pki.certificateToPem(cert)
const keyPem = pki.privateKeyToPem(keys.privateKey)
fs.writeFileSync('ca-cert.pem', pem)
fs.writeFileSync('ca-cert.key', keyPem)

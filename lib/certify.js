const path = require('path')
const crypto = require('crypto')
const pify = require('pify')
const fs = pify(require('fs'))
const forge = require('node-forge')
const pki = forge.pki
const BigNumber = require('bignumber.js')
const ursa = require('ursa')

const CERTS_PATH = path.resolve(__dirname, '..', 'certs')
const CA_SERVER_CERT_PATH = path.resolve(CERTS_PATH, 'ca-server.pem')
const CA_SERVER_CERT_KEY_PATH = path.resolve(CERTS_PATH, 'ca-server.key')
const CA_MACHINE_CERT_PATH = path.resolve(CERTS_PATH, 'ca-machine.pem')
const CA_MACHINE_CERT_KEY_PATH = path.resolve(CERTS_PATH, 'ca-machine.key')
const SERVER_CERT_PATH = path.resolve(CERTS_PATH, 'cert-server.pem')
const SERVER_CERT_KEY_PATH = path.resolve(CERTS_PATH, 'cert-server.key')

exports.issueServerCA = function issueServerCA (domain, org) {
  return issueCA(domain, org, CA_SERVER_CERT_KEY_PATH, CA_SERVER_CERT_PATH)
}

exports.issueMachineCA = function issueServerCA (domain, org) {
  return issueCA(domain, org, CA_MACHINE_CERT_KEY_PATH, CA_MACHINE_CERT_PATH)
}

exports.issueServerCert = function issueServerCert (domain, org) {
  const keyPem = ursa.generatePrivateKey()
  const key = pki.privateKeyFromPem(keyPem)
  const csrPem = buildServerCSR(key, domain, org)
  const cert = issue(csrPem, CA_SERVER_CERT_KEY_PATH, CA_SERVER_CERT_PATH)
  return fs.writeFile(SERVER_CERT_KEY_PATH, keyPem)
  .then(() => fs.writeFile(SERVER_CERT_PATH, cert))
}

exports.issueMachineCert = function issueMachineCert (csrPem) {
  return issue(csrPem, CA_MACHINE_CERT_KEY_PATH, CA_SERVER_CERT_PATH)
}

function buildServerCSR (key, domain, org) {
  const pubkey = pki.rsa.setPublicKey(key)
  var csr = forge.pki.createCertificationRequest()
  csr.publicKey = pubkey

  csr.setSubject([{
    name: 'commonName',
    value: domain
  }, {
    name: 'organizationName',
    value: org
  }])

  csr.sign(key)

  return pki.certificationRequestToPem(csr)
}

function issue (csrPem, caKeyPath, caPath) {
  const csr = pki.certificationRequestFromPem(csrPem)
  if (!csr.verify()) return Promise.reject(new Error('Invalid CSR'))

  Promise.all([
    fs.readFile(CA_SERVER_CERT_PATH),
    fs.readFile(caPath),
    fs.readFile(caKeyPath)
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
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 100)
    cert.setSubject(csr.subject.attributes)
    cert.setIssuer(caCert.subject.attributes)
    cert.sign(caKey, forge.md.sha256.create())
    const certPem = pki.certificateToPem(cert)

    return {certificate: certPem, ca: caServerPem}
  })
}

function issueCA (domain, org, keyPath, certPath) {
  const keyPem = ursa.generatePrivateKey()
  const key = pki.privateKeyFromPem(keyPem)
  const pubkey = pki.rsa.setPublicKey(key)
  const cert = pki.createCertificate()
  cert.publicKey = pubkey
  const randomHex = '0x' + crypto.randomBytes(16).toString('hex')
  cert.serialNumber = new BigNumber(randomHex).toFixed()
  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 100)
  const attrs = [{
    name: 'commonName',
    value: domain
  }, {
    name: 'organizationName',
    value: org
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
  cert.sign(key)
  const pem = pki.certificateToPem(cert)
  return fs.writeFile(certPath, pem)
}

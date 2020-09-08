var express = require('express');
var app = express();
var path = require('path');
var axios = require('axios');
var bodyParser = require('body-parser');
var fs = require('fs');
var https = require('https');
var forge = require('node-forge');

var urlencodedParser = bodyParser.urlencoded({ extended: false })

app.get('/', function (req, res) {
  res.sendFile(path.join(__dirname + '/login.html'))
});

app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});

//This is the endpoint the page posts to. Internally we're going to figure out
//where it really goes. To Okta, to a 3rd party, etc.
app.post('/authenticate', urlencodedParser, function (req, res) {
//Eventually will want a regex that will determine where the user might auth to.
  var url = 'http://127.0.0.1:3000/mockAuthService';

  axios.post(url, {
    userName: req.body.userName,
    password: req.body.password
  })
  .then((response) => {
    console.log(response);
    var caKey = forge.pki.privateKeyFromPem(fs.readFileSync('ca/ca.key'));
    var caCert = forge.pki.certificateFromPem(fs.readFileSync('ca/ca.crt'));

    var newClientKey = forge.pki.rsa.generateKeyPair(2048);
    var newClientCertificate = forge.pki.createCertificate();
    newClientCertificate.publicKey = newClientKey.publicKey;
    newClientCertificate.serialNumber = '01';

    newClientCertificate.validity.notBefore = new Date();
    newClientCertificate.validity.notAfter = new Date();
    newClientCertificate.validity.notAfter.setFullYear(newClientCertificate.validity.notBefore.getFullYear() + 1);


    var attrs = [{
      name: 'commonName',
      value: 'dan.cinnamon@okta.com'
    }];
    newClientCertificate.setSubject(attrs)
    //newClientCertificate.setIssuer(attrs)
    newClientCertificate.setIssuer(caCert.subject.attributes)
    newClientCertificate.setExtensions([{
      name: 'basicConstraints',
      cA: false
    }, {
      name: 'keyUsage',
      keyCertSign: false,
      digitalSignature: true,
      nonRepudiation: false,
      keyEncipherment: false,
      dataEncipherment: false
    }, {
      name: 'extKeyUsage',
      serverAuth: false,
      clientAuth: true,
      codeSigning: false,
      emailProtection: false,
      timeStamping: false
    }, {
      name: 'subjectAltName',
      altNames: [{
        type: 1, // URI
        value: 'dan.cinnamon@okta.com'
      }]
    }, {
      name: 'subjectKeyIdentifier'
    },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes()
    },
    {
      name: 'cRLDistributionPoints',
      altNames: [{type: 6, value: 'https://s3.amazonaws.com/third.party.login.crl/crl.pem'}]
    }]);
    newClientCertificate.sign(caKey, forge.md.sha256.create());
  //  newClientCertificate.sign(newClientKey.privateKey);
    var pem = forge.pki.certificateToPem(newClientCertificate)
    console.log(newClientCertificate)
    console.log(pem)


    const httpsAgent = new https.Agent({
      cert: pem,
      key: forge.pki.privateKeyToPem(newClientKey.privateKey)
    });

    axios.post('https://smartfhir-demo.mtls.oktapreview.com/api/internal/v1/authn/cert', "", {httpsAgent})
    //axios.get('https://smartfhir-demo.mtls.oktapreview.com/api/internal/v1/authn/cert', {httpsAgent})
    .then((response) => {
      console.log(response)
      
      res.send(response.data)
    }, (error) => {
      console.log(error)
    })

    })
})

//This page will be rendered after authentication.
//This is another app in Okta that will display the patient IDs the user has access to.
//Once they pick one, we'll store that in a local cache that Okta hooks will use.

//Let's keep this out for now.  Can use it later.
//app.get('/patient-picker', function (req, res) {


//});

//This is the internal mock-up service that will pretend to be a 3rd party.
app.post('/mockAuthService', function (req, res) {
  res.setHeader('Content-Type', 'application/json');
  console.log('MOCK SERVICE')
  res.json({AuthResult: 'SUCCESS'})
})

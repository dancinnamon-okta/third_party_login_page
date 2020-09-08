// ExpressJS Setup
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser(process.env.STATE_COOKIE_SIGNATURE_KEY));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'))

//Internal Libraries
const authn_logic = require('./authn_logic');
const mock_auth_service = require('./mock_auth_service');
const utils = require('./utils')

// External Libraries
const path = require('path');
const fs = require('fs');
const njwt = require('njwt');
const pem2jwk = require('pem-jwk').pem2jwk

//Authorize Endpoint. Will cache the state sent by the client, and will display a login page.
app.get('/authorize', function (req, res) {
  //Need to store the state parameter the user sent in so we can include it in the redirect.
  //We don't want anything on the page messing with the state parameter, so we'll cache it in a signed cookie and get it later.
  if(utils.validate_authorize_request(req)) {
    res.cookie('stateToken', req.query.state, {httpOnly: true, signed: true});
    res.sendFile(path.join(__dirname + '/login.html'))
  }
  else {
    res.send("The authorize request was not valid. Check to ensure you sent proper clientid, redirect_uri, state, and response type.")
  }
});

//Token Endpoint - will be invoked by Okta at near the end of the process to retrieve a valid id/access token for the user.
app.post('/token', function (req, res) {
  console.log("Inbound token request:")
  console.log(req)
  if(utils.validate_token_request) {
    var inputAuthCode = req.body.code;
    var authCodeJwt = utils.validate_authcode_jwt(inputAuthCode)
    if(authCodeJwt) {
      console.log("Inbound authcode JWT verified:")
      console.log(authCodeJwt)
      var signingKey = fs.readFileSync('ca/jwtkey.pem')
      var jwk = pem2jwk(signingKey)
      var claims = {
        iss: process.env.ISSUER,
        scope: "openid, email, profile",
        aud: process.env.CLIENT_ID,
        sub: authCodeJwt.body.userRecord.username,
        given_name: authCodeJwt.body.userRecord.firstName,
        family_name: authCodeJwt.body.userRecord.lastName,
        email: authCodeJwt.body.userRecord.email,
        globalID: authCodeJwt.body.userRecord.globalID
      }

      var jwt = njwt.create(claims, signingKey, "RS256");

      console.log("Output final JWT:")
      console.log(jwt)

      var returnData = {
        access_token: jwt.compact(),
        id_token: jwt.compact(),
        scope: "openid, email, profile",
        token_type: "Bearer",
        expires_in: 3600
      }
      console.log("Final /token data returned:")
      console.log(returnData)
      res.send(returnData)
    }
    else {
      res.send("The authorization code sent in is not valid.")
    }
  }
  else {
    res.send("The token request was not valid. Check your client credentials, your redirect_uri, or your grant type.")
  }
})

//Keys Endpoint - This is the public keys endpoint that will publish our public signing key.
app.get('/keys', function (req, res) {
  var signingKeyPublic = fs.readFileSync('ca/jwtkey_public.pem')
  var jwkPublic = pem2jwk(signingKeyPublic)
  res.send({ keys: [jwkPublic] })
})

//This is the authentication endpoint the page posts to. The authentication logic is in the "authn_logic.js" file.
app.post('/authenticate', function (req, res) {

  authn_logic.get_authenticated_user(req.body.userName, req.body.password)
  .then((response) => {
    //If we've made it here, then we have a successful response from the 3rd party authn service.
    console.log("Response from get_authenticated_user: ")
    console.log(response)
    //Get our state value that we tucked away, and send the user to the callback URL.
    var authState = req.signedCookies.stateToken
    var authCode = utils.generate_authcode_jwt(response.user)
    var url = process.env.REDIRECT_URI + '?code=' + authCode + "&state=" + authState

    res.redirect(url)
  })
  .catch((error) => {
    console.log(error)
    res.send('Authentication failed!')
  })
})

//This is the internal mock-up service that will pretend to be a 3rd party.
app.post('/mockAuthService', mock_auth_service)

app.listen(3000, function () {
  console.log('Custom smart login Page Started!');
});

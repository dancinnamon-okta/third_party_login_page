const njwt = require('njwt');
const fs = require('fs');

function generate_authcode_jwt(userRecord) {
  var signingKey = fs.readFileSync('ca/authcodekey.pem');

  var claims = {
    userRecord: userRecord
  };

  var jwt = njwt.create(claims,signingKey);
  jwt.setExpiration(new Date().getTime() + (60*5*1000)); // 5 minute expiration

  console.log("Authcode JWT:")
  console.log(jwt)
  return jwt.compact();
}

function validate_authcode_jwt(jwt) {
  var signingKey = fs.readFileSync('ca/authcodekey.pem');
  try {
    return njwt.verify(jwt, signingKey)
  }
  catch(err) {
    console.log("The authorization code passed in is not valid.")
    return false
  }
}

function validate_token_request(req) {
  //Validate client id & secret
  //Validate redirect uri
  //Validate grant type
  if(!req.body.client_id || !req.body.client_secret || !req.body.redirect_uri || !req.body.grant_type) {
    return false
  }
  else if(req.body.client_id != process.env.CLIENT_ID || req.body.client_secret != process.env.CLIENT_SECRET) {
    return false
  }
  else if(req.body.redirect_uri != process.env.REDIRECT_URI) {
    return false
  }
  else if(req.body.grant_type != 'authorization_code') {
    return false
  }
  else {
    return true
  }
}

function validate_authorize_request(req) {
  //Validate client id
  //Validate redirect uri
  //Validate response type
  //Validate state
  if(!req.query.state || !req.query.client_id || !req.query.redirect_uri || !req.query.response_type) {
    return false
  }
  else if(req.query.client_id != process.env.CLIENT_ID || req.query.redirect_uri != process.env.REDIRECT_URI || req.query.response_type != 'code') {
    return false
  }
  else {
    return true
  }
}

module.exports = {
  generate_authcode_jwt: generate_authcode_jwt,
  validate_authcode_jwt: validate_authcode_jwt,
  validate_token_request: validate_token_request,
  validate_authorize_request: validate_authorize_request
}

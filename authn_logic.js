var axios = require('axios');


//Customers can put whatever logic they need to in here. By default we're calling an Okta API for authn.
//Below is another example that calls the internal mock auth service.
function get_authenticated_user(username, password) {
  var url = process.env.OKTA_ORG + '/api/v1/authn';

  let promise = new Promise(function(resolve, reject) {
    //Make an asynchronous call out to the API that we'll use to validate the user.
    //It is expected that this API will pass back some basic user info.
    axios.post(url, {
    username: username,
    password: password
    })
    .then((response) => {
      console.log("Response from authentication service:")
      console.log(response)
      if(response.data.status == 'SUCCESS') {
        var userRecord = {
          username: response.data._embedded.user.profile.login,
          firstName: response.data._embedded.user.profile.firstName,
          lastName: response.data._embedded.user.profile.lastName,
          email: response.data._embedded.user.profile.login,
          globalID: response.data._embedded.user.id
        }
        resolve({status: 'SUCCESS', user: userRecord})
      }
      else {
        reject({status: 'FAILURE', message: "Login failed. The external login service reported failure."})
      }
    })
    .catch((error) => {
      reject({status: 'FAILURE', message: "Login failed. Failure in calling the login service. Error: " + error})
    })
  });

  return promise
}


//Here is an example calling the mock auth service.
function get_authenticated_user_mock(username, password) {
  var url = 'https://purple-stream-subway.glitch.me/mockAuthService';

  let promise = new Promise(function(resolve, reject) {
    //Make an asynchronous call out to the API that we'll use to validate the user.
    //It is expected that this API will pass back some basic user info.
    axios.post(url, {
    userName: username,
    password: password
    })
    .then((response) => {
      console.log("Response from authentication service:")
      console.log(response)
      if(response.data.AuthResult == 'SUCCESS') {
        var userRecord = {
          username: username,
          firstName: response.data.firstName,
          lastName: response.data.lastName,
          email: response.data.email,
          globalID: response.data.globalID
        }
        resolve({status: 'SUCCESS', user: userRecord})
      }
      else {
        reject({status: 'FAILURE', message: "Login failed. The external login service reported failure."})
      }
    })
    .catch((error) => {
      reject({status: 'FAILURE', message: "Login failed. Failure in calling the login service. Error: " + error})
    })
  });

  return promise
}

module.exports = {
  get_authenticated_user: get_authenticated_user
};

const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const AWS = require("aws-sdk");
const request = require("request");
const jwkToPem = require("jwk-to-pem");
const jwt = require("jsonwebtoken");
global.fetch = require("node-fetch");
var LocalStorage = require('node-localstorage').LocalStorage,
localStorage = new LocalStorage('./scratch');

const dotenv = require('dotenv');
dotenv.config();

const poolData = {
  UserPoolId: process.env.COGNITO_USER_POOL_ID, 
  ClientId: process.env.COGNITO_CLIENT_ID, 
};
const pool_region = process.env.COGNITO_POOL_REGION;

const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

function validateToken(callback) {
    var cognitoUser = userPool.getCurrentUser();
    console.log('logged cognito user:', cognitoUser);
    var validationResult = "";
    
    request({
        url: `https://cognito-idp.${pool_region}.amazonaws.com/${poolData.UserPoolId}/.well-known/jwks.json`,
        json: true
    }, function (error, response, body) {
        if (!error && response.statusCode === 200) {
            pems = {};
            var keys = body['keys'];
            for(var i = 0; i < keys.length; i++) {
                //Convert each key to PEM
                var key_id = keys[i].kid;
                var modulus = keys[i].n;
                var exponent = keys[i].e;
                var key_type = keys[i].kty;
                var jwk = { kty: key_type, n: modulus, e: exponent};
                var pem = jwkToPem(jwk);
                pems[key_id] = pem;
            }
            //validate the token
            var decodedJwt = jwt.decode(localStorage.getItem('accessToken'), {complete: true});
            if (!decodedJwt) {
                console.log("Not a valid JWT token");
                validationResult="Invalid Token";
                return;
            }

            var kid = decodedJwt.header.kid;
            var pem = pems[kid];
            if (!pem) {
                console.log('Invalid token');
                validationResult="Invalid Token";
                return;
            }

            jwt.verify(localStorage.getItem('accessToken'), pem, function(err, payload) {
                if(err) {
                    console.log("Invalid Token.");
                    validationResult="Invalid Token";
                } else {
                    console.log("Valid Token.");
                    console.log(payload);
                    validationResult="Valid Token";
                }
            });
        } else {
            console.log("Error! Unable to download JWKs");
            validationResult="Error! Unable to download JWKs";
        }

        callback(validationResult);
    });
}

function login(username, password, callback) {
    var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
        Username : username,
        Password : password,
    });

    var userData = {
        Username : username,
        Pool : userPool
    };

    var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

    console.log('authenticating %s via cognito...', username);

    cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function (result) {
            localStorage.setItem('accessToken',result.getAccessToken().getJwtToken());
            localStorage.setItem('idToken',result.getIdToken().getJwtToken());
            localStorage.setItem('refreshToken',result.getRefreshToken().getToken());
            
            callback(result);
        },
        onFailure: function(err) {
            callback(err);
        },

    });
}

function logout(callback) {
    var cognitoUser = userPool.getCurrentUser();
    
    console.log('logged cognito user:', cognitoUser);

    if (cognitoUser != null) {
        cognitoUser.signOut();
    }

    localStorage.clear();

    callback('success');
}

function refreshToken(callback) {    
    var cognitoUser = userPool.getCurrentUser();
    console.log('logged cognito user:', cognitoUser);
    var refreshResult="";
   
    const RefreshToken = new AmazonCognitoIdentity.CognitoRefreshToken({RefreshToken: localStorage.getItem('refreshToken')});
    
    cognitoUser.refreshSession(RefreshToken, (err, session) => {
        if (err) {
            console.log(err);
            refreshResult=err;
        } else {
            let retObj = {
                "access_token": session.accessToken.jwtToken,
                "id_token": session.idToken.jwtToken,
                "refresh_token": session.refreshToken.token,
            }
            console.log(retObj);
            refreshResult = "refreshed";
        }
        callback(refreshResult);
    });
}

module.exports={
    login,
    logout,
    validateToken,
    refreshToken
}
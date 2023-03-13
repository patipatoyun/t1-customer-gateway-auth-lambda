const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const JWKS_UAT_URI = 'https://passport-uat.the1.co.th/jwks'

const keyClient = jwksClient({
    cache: true,
    cacheMaxAge: 86400000, //value in ms
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    strictSsl: true,
    jwksUri: JWKS_UAT_URI
})

const verificationOptions = {
    // verify claims, e.g.
    // "audience": "urn:audience"
    "algorithms": "RS256"
}

const request = {
    authorizationToken: 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik9PRjRRdFZGZVFHZzdoLWRZcUNKam1lVmVZQkVKZVg2Z04wWTUycFlncVUifQ.eyJmaXJzdF9sb2dpbiI6ZmFsc2UsImp0aSI6IlN6NDhaNmNNM250bExzeFZBMmhyMCIsInN1YiI6ImI1MjZkOWRhLTA2OWMtNGFmZi1hMzFhLTk3MWFkNzZhOWExYiIsImlhdCI6MTY3Nzc3MzY3NSwiZXhwIjoxNjc3Nzc3Mjc1LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBtb2JpbGUiLCJpc3MiOiJodHRwczovL3Bhc3Nwb3J0LXVhdC50aGUxLmNvLnRoIiwiYXVkIjoiZDUxZmM4NWYtZjkxOC00ZjA3LWE3ZmItYTg5NWNkZTZlOGNjIn0.tAEjhaN1hHdQgvSUX4b3NpNZiMskWvXaPhCejmzzI9JHewx-YhUVoHO1s80c6WQau3njncSsv2iRbQMME8Sl8pQNgPzMCV0VX63JQO1WpJw_cAgnOLqt5k2NAiiTxTOj99yy_33FuQdDuPXTJCs9Xn7p3SyyYQIU9ri4_loFTp7J45KBfSkj60AbEzwEgbm_AaRpRafFX0-NiLb9vsFE6O2MHFs2PQnB5XQNFwX02N6he5_ccfNKMeEr5--GvKlreSa8f__fiFwTJQv4GHN1-36tfc8Ut-TTjo86W8jOh9i-PCtuY3PZsuYeQCWF7yEFmFgmHPKhOHZiLhWz7Sr6pg'
}

function extractTokenFromHeader(event, callback) {
    let token = event.authorizationToken;
    let match = token.match(/^Bearer (.*)$/);
    if (!token || !match || match.length < 2) {
        console.log('extractTokenFromHeader error: ' + token);
        callback("Unauthorized")
    }
    return match[1];
}

function getKidByJwtDecoder(token, callback) {
    try {
        let decoded = jwt.decode(token, { complete: true });
        return decoded.header.kid;
    } catch (error) {
        console.log("JwtDecoder error:", error);
        callback("Unauthorized");
    }
}

function generatePolicy(principalId, effect, resource, accessToken, errorMessage) {
    let authResponse = {
        "principalId": principalId,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        }
    }
    authResponse.context = {
        "token": accessToken,
        "errorMessage": errorMessage || null
    };
    console.log("generate policy ", effect, " : ", authResponse.principalId);
    return authResponse;
}

function errorMsgDenyPolicy(error) {
    switch (true) {
        case error instanceof jwt.TokenExpiredError: return "Token expired";
        default: return "Token invalid";
    }
}

exports.handler = function (event, context, callback) {
    let token = extractTokenFromHeader(event, callback);
    let kid = getKidByJwtDecoder(token, callback);

    keyClient.getSigningKey(kid, function (err, key) {
        if (err) {
            console.log("getSigningKey error:", err);
            // callback("Unauthorized");
        } else {
            let signingKey = key.publicKey || key.rsaPublicKey;
            console.log("signingKey: " + signingKey);
            jwt.verify(token, signingKey, verificationOptions, function (error) {
                if (error) {
                    console.log("error!!!" + error)
                    //callback(null, generatePolicy('user', 'Deny', event.methodArn, event.authorizationToken, errorMsgDenyPolicy(error)));
                } else {
                    console.log("pass!!!")
                    //callback(null, generatePolicy('user', 'Allow', 'event.methodArn', event.authorizationToken));
                }
            })
        }
    })
}

module.exports.handler();
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

function extractTokenFromHeader(event) {
    let token = event.authorizationToken;
    if (!token) throw new Error("Expected 'event.authorizationToken' parametere to be set");

    let match = token.match(/^Bearer (.*)$/);
    if (!match || match.length < 2) throw new Error("Invalid Authorization token -" + token + " does not match the bearer");

    return match[1];
}

function getKidByJwtDecoder(token) {
    try {
        let decoded = jwt.decode(token, { complete: true });
        return decoded.header.kid;
    } catch (error) {
        throw new Error("JwtDecoder error: " + error);
    }
}

function generatePolicy(principalId, effect, resource, bearerToken) {
    let authResponse = {
        "principalId": principalId,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "lambda:InvokeFunction",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        }
    }
    authResponse.context = {
        "name": bearerToken
    };
    console.log("generate policy success: ", authResponse.principalId);
    return authResponse;
}

exports.handler = function (event, context, callback) {
    let token = extractTokenFromHeader(request);
    let kid = getKidByJwtDecoder(token);

    keyClient.getSigningKey(kid, function (err, key) {
        if (err) {
            console.log("getSigningKey error:", err);
            // callback("Unauthorized");
        } else {
            let signingKey = key.publicKey || key.rsaPublicKey;
            console.log("signingKey: " + signingKey);
            jwt.verify(token, signingKey, verificationOptions, function (error) {
                if (error) {
                    console.log("jwt verify error: " + error)
                    //callback(null, generatePolicy('user', 'Deny', 'event.methodArn', 'event.authorizationToken'));
                } else {
                    console.log("pass!!!")
                    //callback(null, generatePolicy('user', 'Allow', 'event.methodArn', event.authorizationToken));
                }
            })
        }
    })
}

module.exports.handler();
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
            "Version": "2023-13-10",
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
            callback("Unauthorized");
        } else {
            let signingKey = key.publicKey || key.rsaPublicKey;
            console.log("signingKey: " + signingKey)
            jwt.verify(token, signingKey, verificationOptions, function (error) {
                if (error) {
                    callback(null, generatePolicy('user', 'Deny', 'event.methodArn', 'event.authorizationToken'));
                } else {
                    callback(null, generatePolicy('user', 'Allow', 'event.methodArn', event.authorizationToken));
                }
            })
        }
    })
}
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const JWKS_URI = 'https://the1-corporate-iam.cloud-iam.com/auth/realms/integration-np/protocol/openid-connect/certs'

const keyClient = jwksClient({
    cache: true,
    cacheMaxAge: 86400000, //value in ms
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    strictSsl: true,
    jwksUri: JWKS_URI,
    requestHeaders: {
        'user-agent': 'AWSAuthorizer'
    }
})

const verificationOptions = {
    // verify claims, e.g.
    // "audience": "urn:audience"
    "algorithms": "RS256"
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
            callback("Unauthorized");
        } else {
            let signingKey = key.publicKey || key.rsaPublicKey;
            jwt.verify(token, signingKey, verificationOptions, function (error) {
                if (error) {
                    callback(null, generatePolicy('user', 'Deny', event.methodArn, event.authorizationToken, errorMsgDenyPolicy(error)));
                } else {
                    callback(null, generatePolicy('user', 'Allow', event.methodArn, event.authorizationToken));
                }
            })
        }
    })
}
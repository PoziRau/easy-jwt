const crypto = require("crypto");

exports.sign = (json, secret, params) => {

    if (params === undefined) { params = {} }

    if (params.alg === null) { 
        crypt = 'sha256', algorithm = 'HS256' 
    } else { 
        algorithm = params.alg 

        if (algorithm === 'HS256') { 
            crypt = 'sha256' 
        } else if (algorithm === 'HS384') { 
            crypt = 'sha384' 
        } else if (algorithm === 'HS512') { 
            crypt = 'sha512' 
        } else { 
            throw new Error(JSON.stringify({ name: 'SignError', message: 'invalid algorithm' }, null, 3)) 
        }
    }

    if (params.expireDate == null) { expiry = -1 } else { expiry = params.expireDate }
    if (json == null) { throw new Error(JSON.stringify({ name: 'SignError', message: 'payload is required' }, null, 3)) }
    if (secret == null) { throw new Error(JSON.stringify({ name: 'SignError', message: 'secret is required' }, null, 3)) }

    header = { alg: algorithm, typ: "JWT", expireDate: expiry}
    return Buffer.from(JSON.stringify(header)).toString('base64') + '.' + Buffer.from(JSON.stringify(json)).toString('base64') + '.' + crypto.createHmac(crypt, secret).update(JSON.stringify(header) + JSON.stringify(json)).digest("base64");
}

exports.verify = (data, secret, options) => {

    if (options == undefined) { options = {} }

    if (options.maxAge != null) { maxAge = options.maxAge } else { maxAge = 0 }

    if (data.includes(".", 3)) { var data = data.split('.') } else { throw new Error(JSON.stringify({ name: 'TokenError', message: 'incorrect token format' }, null, 3)) }

    if (secret == null) { throw new Error(JSON.stringify({ name: 'TokenError', message: 'secret is required' }, null, 3)) }

    newdata = JSON.parse(Buffer.from(data[0], 'base64').toString('ascii'))

    if (newdata.alg === 'HS256') { 
        crypt = 'sha256' 
    } else if (newdata.alg === 'HS384') { 
        crypt = 'sha384' 
    } else if (newdata.alg === 'HS512') { 
        crypt = 'sha512' 
    } else { 
        throw new Error(JSON.stringify({ name: 'TokenError', message: 'invalid algorithm' }, null, 3)) 
    }

    if (data[2] == crypto.createHmac(crypt, secret).update(Buffer.from(data[0], 'base64').toString('ascii')) + Buffer.from(data[1], 'base64').toString('ascii').digest("base64")) {

        expired = JSON.parse(Buffer.from(data[0], 'base64').toString('ascii')).expireDate

        if (expired + maxAge >= Date.now() || expired == -1 || options.ignoreExpiration == true) {
            
            if (options.complete === true) {
                return JSON.parse('{"payload":' + Buffer.from(data[0], 'base64').toString('ascii').toString('ascii') + ',"body":' + Buffer.from(data[1], 'base64').toString('ascii').toString('ascii') + '}') 
            } else {
                return JSON.parse(Buffer.from(data[1], 'base64').toString('ascii').toString('ascii')) 
            }

        } else {
            throw new Error(JSON.stringify({ name: 'TokenError', message: 'token expired' }, null, 3))
        }

    } else {
        throw new Error(JSON.stringify({ name: 'TokenError', message: 'invalid token signature' }, null, 3))
    }
}
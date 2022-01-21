const crypto = require("crypto");

exports.sign = (json, secret, params) => {

    if (params == undefined) { params = {} }

    if (params.alg == null) { 
        crypt = 'sha512', algorithm = 'HS512' 
    } else { 
        algorithm = params.alg 

        if (algorithm == 'HS256') { 
            crypt = 'sha256' 
        } else if (algorithm == 'HS384') { 
            crypt = 'sha384' 
        } else if (algorithm == 'HS512') { 
            crypt = 'sha512' 
        } else { 
            throw new Error(JSON.stringify({ name: 'SignError', message: 'invalid algorithm type' })) 
        }
    }

    if (params.expireDate == null) { expiry = -1 } else { expiry = params.expireDate }
    if (json == null) { throw new Error(JSON.stringify({ name: 'SignError', message: 'data is required' })) }
    if (secret == null) { throw new Error(JSON.stringify({ name: 'SignError', message: 'secret is required' })) }

    header = { alg: algorithm, typ: "JWT", expireDate: expiry}
    return btoa(JSON.stringify(header)) + '.' + btoa(JSON.stringify(json)) + '.' + crypto.createHmac(crypt, secret).update(JSON.stringify(header) + JSON.stringify(json)).digest("base64");
}

exports.verify = (data, secret, options) => {

    if (options == undefined) { options = {} }

    if (options.maxAge != null) { maxAge = options.maxAge } else { maxAge = 0 }

    if (data.includes(".", 3)) { var data = data.split('.') } else { throw new Error(JSON.stringify({ name: 'TokenError', message: 'incorrect token format' })) }

    if (secret == null) { throw new Error(JSON.stringify({ name: 'TokenError', message: 'secret is required' })) }

    newdata = JSON.parse(atob(data[0]))

    if (newdata.alg == 'HS256') { 
        crypt = 'sha256' 
    } else if (newdata.alg == 'HS384') { 
        crypt = 'sha384' 
    } else if (newdata.alg == 'HS512') { 
        crypt = 'sha512' 
    } else { 
        throw new Error(JSON.stringify({ name: 'TokenError', message: 'invalid algorithm type' })) 
    }

    if (data[2] == crypto.createHmac(crypt, secret).update(atob(data[0]) + atob(data[1])).digest("base64")) {

        expired = JSON.parse(atob(data[0]).toString('ascii')).expireDate

        if (expired + maxAge >= Date.now() || expired == -1 || options.ignoreExpiration == true) {
            
            if (options.complete == true) {
                return JSON.parse('{"payload":' + atob(data[0]).toString('ascii') + ',"body":' + atob(data[1]).toString('ascii') + '}') 
            } else {
                return JSON.parse(atob(data[1]).toString('ascii')) 
            }

        } else {
            throw new Error(JSON.stringify({ name: 'TokenExpired', message: 'token expired' }))
        }

    } else {
        throw new Error(JSON.stringify({ name: 'TokenError', message: 'invalid token signature' }))
    }
}
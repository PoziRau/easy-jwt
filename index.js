const crypto = require("crypto");

exports.token = (json, secret) => {
    header = { alg: "HS256", typ: "JWT"}
    return btoa(JSON.stringify(header)) + '.' + btoa(JSON.stringify(json)) + '.' + crypto.createHmac('sha256', secret).update(header + json).digest("base64");
}

exports.verify = (data, secret) => {
    var data = data.split('.') 

    if (secret == null) { return atob(data[1]) (Error ('No secret provided, verification not complete')) }

    if (data[2] === crypto.createHmac('sha256', secret).update(atob(data[0]) + atob(data[1])).digest("base64")) {
        return data[1].toString('ascii')
    } else {
        throw new Error('Failed verification')
    }
}
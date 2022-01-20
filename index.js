const crypto = require("crypto");

exports.token = (json, secret) => {
    header = { alg: "HS256", typ: "JWT"}
    return header.toString('base64') + '.' + json.toString('base64') + '.' + crypto.createHmac('sha256', secret).update(header + json).digest("base64");
}

exports.verify = (data, secret) => {
    var data = data.split('.') 

    if(secret == null) { return data[1].toString('ascii') (Error ('No secret provided, verification not complete')) }

    if (data[2] === crypto.createHmac('sha256', secret).update(data[0] + data[1]).digest("base64")) {
        return data[1].toString('ascii')
    } else {
        return data (Error ('Failed verification'))
    }
}
  
exports.allColors = allColors;
import crypto from 'crypto'

type JSONValue = string | number | boolean | { [x: string]: JSONValue } | Array<JSONValue>

type JSONObject = {
  [x: string]: JSONValue
}

const removeBase64Padding = (data: string) =>
  data.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

const sign = (
  payload: JSONObject | null = null,
  secret: crypto.BinaryLike | crypto.KeyObject | null,
  options:
    | { alg?: 'HS256' | 'HS384' | 'HS512'; expireDate?: number }
    | { alg: 'HS256'; expireDate: -1 }
) => {
  const algorithm = options?.alg ?? 'HS256'
  const expiry = options?.expireDate ?? -1

  let crypt = 'sha256'

  if (algorithm === 'HS384') {
    crypt = 'sha384'
  } else if (algorithm === 'HS512') {
    crypt = 'sha512'
  } else if (algorithm !== 'HS256') {
    throw new Error(JSON.stringify({ name: 'SignError', message: 'Invalid algorithm' }, null, 2))
  }

  if (!payload) {
    throw new Error(JSON.stringify({ name: 'SignError', message: 'Payload is required' }, null, 2))
  }
  if (!secret) {
    throw new Error(JSON.stringify({ name: 'SignError', message: 'Secret is required' }, null, 2))
  }

  const header = { alg: algorithm, typ: 'JWT', expireDate: expiry }

  const rawHeader = removeBase64Padding(Buffer.from(JSON.stringify(header)).toString('base64'))
  const rawPayload = removeBase64Padding(Buffer.from(JSON.stringify(payload)).toString('base64'))
  return `${rawHeader}.${rawPayload}.${removeBase64Padding(
    crypto.createHmac(crypt, secret).update(`${rawHeader}.${rawPayload}`).digest('base64')
  )}`
}

const verify = (
  data: string = '',
  secret: crypto.BinaryLike | crypto.KeyObject | null,
  options: { maxAge?: any; ignoreExpiration?: any; complete?: any } = { maxAge: 0 }
) => {
  let maxAge = options?.maxAge ?? 0

  let crypt = 'sha256'

  if (typeof data !== 'string') {
    throw new Error(
      JSON.stringify({ name: 'TokenError', message: 'Incorrect token format' }, null, 2)
    )
  }

  const splittedData = data.split('.')
  if (splittedData.length !== 3) {
    throw new Error(
      JSON.stringify({ name: 'TokenError', message: 'Incorrect token format' }, null, 2)
    )
  }

  if (!secret) {
    throw new Error(JSON.stringify({ name: 'TokenError', message: 'Secret is required' }, null, 2))
  }

  const [rawHeader, rawPayload, signature] = splittedData
  const header = JSON.parse(Buffer.from(rawHeader ?? '', 'base64').toString())
  const payload = JSON.parse(Buffer.from(rawPayload ?? '', 'base64').toString())

  const algorithm = header?.alg ?? 'HS256'

  if (algorithm === 'HS384') {
    crypt = 'sha384'
  } else if (algorithm === 'HS512') {
    crypt = 'sha512'
  } else if (algorithm !== 'HS256') {
    throw new Error(JSON.stringify({ name: 'TokenError', message: 'Invalid algorithm' }, null, 2))
  }

  if (
    signature ===
    removeBase64Padding(
      crypto.createHmac(crypt, secret).update(`${rawHeader}.${rawPayload}`).digest('base64')
    )
  ) {
    const expired = header.expireDate

    if (expired + maxAge >= Date.now() || expired === -1 || options.ignoreExpiration === true) {
      if (options.complete === true) {
        return { header, payload }
      } else {
        return payload
      }
    } else {
      throw new Error(JSON.stringify({ name: 'TokenError', message: 'Token expired' }, null, 2))
    }
  } else {
    throw new Error(
      JSON.stringify({ name: 'TokenError', message: 'Invalid token signature' }, null, 2)
    )
  }
}

export { sign, verify }

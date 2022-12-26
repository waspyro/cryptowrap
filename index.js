import crypto from 'crypto'
import os from 'os'
import Path from 'path'
import fs from "fs/promises";
import {mkdirP} from "mkdirp";

const algorithm = "aes-256-cbc"

export const Encryptor = (key, ivlen = 16) => (string) => {
  const iv = crypto.randomBytes(ivlen)
  const cipher = crypto.createCipheriv(algorithm, key, iv)
  return iv.toString('hex') + cipher.update(string, "utf-8", 'hex') +
    cipher.final('hex')
}

export const Decryptor = (key, ivlen = 16) => (encryptedString) => {
  const iv = new Buffer.from(encryptedString.substring(0, ivlen*2), 'hex')
  encryptedString = new Buffer.from(encryptedString.substring(ivlen*2), 'hex')
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decryptedData = decipher.update(encryptedString, "hex", "utf-8");
  decryptedData += decipher.final("utf8");
  return decryptedData
}

export const generateKey = () => crypto.randomBytes(32)

export const cryptowrapKeysFolder = Path.join(os.homedir(), '.local', 'state', 'cryptowrap')

export const readOrCreateNewKeyFile = (filename = 'cryptowrap-secret', fileLocation = cryptowrapKeysFolder) => {
  const path = Path.join(fileLocation, filename)
  return fs.readFile(path).catch(e => {
    if(e.code !== 'ENOENT') throw e
    return mkdirP(fileLocation).then(() => {
      const key = generateKey()
      return fs.writeFile(path, key).then(() => key)
    })
  })
}

export const init = (key = readOrCreateNewKeyFile(), ivlen = 16, encodingFormat = 'json') => {
  const encryptFn = Encryptor(key, ivlen)
  const decryptFn = Decryptor(key, ivlen)

  switch (encodingFormat) {
    default: case 'json':
      return {
        encrypt: data => encryptFn(JSON.stringify(data)),
        decrypt: data => data && JSON.parse(decryptFn(data))
      }

    case 'string':
      return {
        encrypt: encryptFn,
        decrypt: decryptFn
      }
  }

}

export default init


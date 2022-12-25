import crypto from 'crypto'

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

export const Create = (key, ivlen) => {
  return {
    encrypt: Encryptor(key, ivlen),
    decrypt: Decryptor(key, ivlen)
  }
}

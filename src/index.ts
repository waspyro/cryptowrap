import crypto, {Cipher} from 'crypto'
import Path from "path";
import os from "os";
import fs from 'fs/promises'
import mkdirp from 'mkdirp'

type CipherParams = Parameters<typeof Cipher.prototype.update>[0]

export default class Cryptowrap {
    private algorithm = 'aes256'
    private ivlen = 16

    constructor(public readonly key: string | Buffer) {}

    encrypt = (data: CipherParams[0]) => {
        const iv = crypto.randomBytes(16)
        const cipher = crypto.createCipheriv(this.algorithm, this.key, iv)
        const encryption = cipher.update(data, "utf-8", "hex")
        return iv.toString('hex') + encryption + cipher.final('hex')
    }

    decrypt = (srt: string) => {
        const encryptedData = srt.substring(this.ivlen*2)
        const iv = Buffer.from(srt.substring(0, this.ivlen*2), 'hex')
        const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv)
        return decipher.update(encryptedData, 'hex', 'utf-8') + decipher.final('utf-8')
    }

    get args(): [typeof this.encrypt, typeof this.decrypt] {
        return [this.encrypt, this.decrypt]
    }

    static generateKey = () => crypto.randomBytes(32)

    static readOrCreateKeyFile = async (
        name: string = Cryptowrap.envName || Cryptowrap.defaultName,
        location: string = Cryptowrap.envLocation || Cryptowrap.defaultLocation,
        create = true
    ) => {
        const path = Path.join(location, name)
        try {
            return await fs.readFile(path)
        } catch (e: any) {
            if(!create || e?.code !== 'ENOENT') throw e
            await mkdirp(location)
            const key = Cryptowrap.generateKey()
            await fs.writeFile(path, key)
            return key
        }
    }

    static fromFile = (name?: string, location?: string, create?: boolean) =>
        Cryptowrap.readOrCreateKeyFile(name, location, create).then(key => new Cryptowrap(key))

    static defaultLocation = Path.join(os.homedir(), '.local', 'state', 'cryptowrap')
    static defaultName = 'cryptowrap-secret'
    static envName = process.env.CRYPTOWRAP_KEY_NAME
    static envLocation = process.env.CRYPTOWRAP_KEY_LOCATION
}

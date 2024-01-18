/* eslint-disable no-unused-vars */
import fs from 'fs';
import Device from '../common/device.js';
import nodecrypto from 'crypto';


export default class CryptoHelper {

    static createHashFromString(str) {
        var md5Hasher = nodecrypto.createHash("md5");
        var hash = md5Hasher.update(str);
        return hash.digest();
    }

    static createHashFromStringSha256(str) {
        var sha256Hasher = nodecrypto.createHash("sha256");
        var hash = sha256Hasher.update(str);
        return hash.digest('hex').slice(0, 32);
    }

    static encrypt(jsonObj, uuid) {
        var key = this.createHashFromString(uuid);
        var iv = nodecrypto.randomBytes(16);
        var cipher = nodecrypto.createCipheriv("aes-128-cbc", key, iv);
        var buffered_obj = Buffer.from(JSON.stringify(jsonObj), "utf8");
        var a = Buffer.concat([cipher.update(buffered_obj), cipher.final()]);
        return iv.toString("hex") + "|" + a.toString("hex")
    }

    static generateHashFromCertif(cert, hm1, hm2) {
        let cipher = nodecrypto.createDecipheriv("aes-256-ecb", hm2, "");
        let decrypted_cert_bytes = cipher.update(cert.encodedCertificate, "base64")
        let decrypted_certificate = Buffer.concat([decrypted_cert_bytes, cipher.final()]);
        console.log("decrypted_certificate", decrypted_certificate.toString());
        let hash_input = hm1 + decrypted_certificate.toString();
        return nodecrypto.createHash("sha256").update(hash_input).digest("hex");
    }

    static encryptToFile(filePath, jsonObj, uuid) {
        let encryptedJsonObj = this.encrypt(jsonObj, uuid);
        return fs.writeFile(filePath, encryptedJsonObj,
            {
              encoding: "utf8",
              flag: "w"
            },
            (err) => {
              if (err)
                console.log(err);
              else {
                console.log("File written successfully\n");
              }
          });
    }

    static async encryptToFileWithUUID(filePath, jsonObj) {
        const uuid = await Device.getUUID();
        return this.encryptToFile(filePath, jsonObj, uuid);
    }

    /**
     * Decrypt a file and return the decrypted object
     * @param {string} filePath 
     * @returns {Promise<{id: string, certificate: string}>}
     */
    static async decryptFromFileWithUUID(filePath) {
        const uuid = await Device.getUUID();
        console.log("machine uuid", uuid);
        return this.decryptFromFile(filePath, uuid);
    }

    static decryptFromFile(filePath, uuid) {
        let data = fs.readFileSync(filePath, "utf8")
        try {
            return this.decrypt(data, uuid);
        } catch (err) {
            console.log("[1019 CRYPTO_HELPER] cannot decrypt from file", filePath, err);
            throw err;
        }
    }

    /**
     * Decrypt a string using aes-128-cbc algorithm with a key derived from uuid
     * @param {string} data data to decrypt
     * @param {string} uuid uuid to use to decrypt 
     * @returns 
     */
    static decrypt(data, uuid) {
        var r = data.split("|");
        var iv = Buffer.from(r[0], "hex");
        var dataToDecrypt = Buffer.from(r[1], "hex");
        var key = this.createHashFromString(uuid);
        var decipher = nodecrypto.createDecipheriv("aes-128-cbc", key, iv);
        var plainText = decipher.update(dataToDecrypt);
        var u = Buffer.concat([plainText, decipher.final()]).toString();
        r = JSON.parse(u);
        return r;
    }
    /**
     * Hash a file using sha1 asynchronously
     * @param {string} filePath path to the file to hash
     * @returns {Promise<string>} the hash of the file
     */
    static getFileHash(filePath) {
        return new Promise((resolve, reject) => {
            const sha1Hasher = nodecrypto.createHash("sha1");
            const stream = fs.createReadStream(filePath);
            stream.on("error", () => {
                resolve(0)
            })
            stream.on("data", e => {
                sha1Hasher.update(e)
            })
            stream.on("end", () => {
                const e = sha1Hasher.digest("hex");
                resolve(e)
            })
        })
    }

    static getFileHashSync(filePath) {
        const sha1Hasher = nodecrypto.createHash("sha1");
        const fileContent = fs.readFileSync(filePath);
        return sha1Hasher.update(fileContent), sha1Hasher.digest("hex");
    }
}
import path from 'path';
import fs from 'fs';
import os from 'os';
import Haapi from './haapi.js';
import CryptoHelper from './cryptoHelper.js';
import logger from '../common/logger.js';
import Device from '../common/device.js';
import ZAAP_CONFIG from '../common/zaapConfig.js';


export default class AuthHelper {


    static getApikeysFolderPath() {
        return path.join(this.getZaapPath("userData"), "keydata")
    }

    static getZaapPath(flag) {
        if (flag == "userData") {
            return path.join(process.env.AppData, 'zaap')
        }
    }

    static async getStoredCertificate(username) {
        if (!username)
            return Promise.resolve(null);
        const certFolder = this.getCertificateFolderPath();
        const userNameHash = CryptoHelper.createHashFromStringSha256(username);
        var certPath = path.join(certFolder, `.certif${userNameHash}`);
        if (fs.existsSync(certPath)) {
            try {
                return {
                    certificate: await CryptoHelper.decryptFromFileWithUUID(certPath),
                    filepath: certPath
                }
            } catch (e) {
                logger.error(`[1020 AUTH_HELPER] Delete indecipherable certificate on ${certPath}`, e);
                try {
                    fs.unlinkSync(certPath)
                } catch (e) {
                    logger.error(`[1030 AUTH_HELPER] Impossible to delete certificate file : ${e.message}`)
                }
            }
        }
        return Promise.resolve(null)
    }

    static async getAllDecipheredStoredCertificates(certFolder) {
        if (!certFolder)
            certFolder = this.getCertificateFolderPath();
        const certFiles = fs.readdirSync(certFolder);
        const decipheredCerts = [];
        const {hm1, hm2} = this.createHmEncoder();
        let cert, hash;
        for (let i = 0; i < certFiles.length; i++) {
            const certFile = certFiles[i];
            if (certFile.startsWith(".certif")) {
                const certPath = path.join(certFolder, certFile);
                console.log(`processing file ${certPath}`)
                try {
                    cert = await CryptoHelper.decryptFromFileWithUUID(certPath);
                    hash = this.generateHashFromCertif(cert, hm1, hm2);
                    decipheredCerts.push({hash, certFile, cert})
                } catch (e) {
                    console.log(`[1020 AUTH_HELPER] ${e}`);
                }
            }
        }
        return decipheredCerts
    }

    static async getAllDecipheredStoredApiKeys(apikeysFolder) {
        if (!apikeysFolder)
            apikeysFolder = this.getApikeysFolderPath();
        const apiKeyFiles = fs.readdirSync(apikeysFolder);
        const decipheredApiKeys = [];
        for (let i = 0; i < apiKeyFiles.length; i++) {
            const apikeyFile = apiKeyFiles[i];
            console.log(`processing file ${apikeyFile}`)
            try {
                const apikeyPath = path.join(apikeysFolder, apikeyFile);
                const apikey = await CryptoHelper.decryptFromFileWithUUID(apikeyPath);
                decipheredApiKeys.push({apikeyFile, apikey})
            } catch (e) {
                console.log(`[1020 AUTH_HELPER] ${e}`);
            }
        }
        return decipheredApiKeys
    }

    static async generateApiForAccount(username, password) {
        return this.getStoredCertificate(username).then(async r => {
            if (r) {
                const {
                    certificate: certificate,
                    filepath: filepath
                } = r;
                let certHash;
                try {
                    certHash = this.generateHashFromCertif(certificate);
                } catch (r) {
                    logger.error(`[1022 AUTH_HELPER] Error on generateHashFromCertif, \n ${r} \n delete certificate on ${filepath}`);
                    try {
                        fs.unlinkSync(filepath)
                    } catch (e) {
                        logger.warn(`[1032 AUTH_HELPER] Impossible to delete certificate file : ${e.message}`)
                    }
                    return Haapi.createApikey(username, password).then(e => e)
                }
                const certId = certificate.id;
                return Haapi.createApikey(username, password, certId, certHash).then(e => (e.certificate = certificate, e))
            }
            return Haapi.createApikey(username, password).then(r => r)
        })
    }

    static async refreshApikey(apiKey) {
        if (apiKey.refreshDate && apiKey.refreshDate + 1728e5 > (new Date).getTime())
            return Promise.resolve();
        else Haapi.refreshApikey(apiKey).then(({
            refreshToken: refreshToken
        }) => {
            if(!apiKey) {
                logger.error("apiKey not found while refreshing it")
            } else {
                apiKey.refreshToken = refreshToken
                apiKey.refreshDate = (new Date).getTime()
            }
        }).catch(e => {
            throw logger.error("[1114 AUTH] unable to refresh api key", e), e
        })
    }

    static generateHashFromCertif(cert, hm1, hm2) {
        if (!hm1 || !hm2)
            ({hm1, hm2} = this.createHmEncoder());
        return CryptoHelper.generateHashFromCertif(cert, hm1, hm2)
    }

    static getCertificateFolderPath() {
        return path.join(this.getZaapPath("userData"), 'certificate');
    }

    getApiKeysFolderPath() {
        return path.join(this.getZaapPath("userData"), "keydata")
    }

    static createHmEncoder() {
        let data = [];
        data.push(os.arch());
        data.push(os.platform());
        data.push(Device.machineIdSync());
        data.push(os.userInfo().username);
        data.push(Device.getOsVersion());
        data.push(Device.getComputerRam());
        let machineInfos = data.join("");
        logger.info(`[1010 AUTH_HELPER] Machine infos : ${data}`)
        const hm1 = CryptoHelper.createHashFromStringSha256(machineInfos);
        const hm2 = hm1.split("").reverse().join("");
        return {hm1, hm2}
    }

    static async storeCertificate(certificate) {
        if (!certificate.login) 
            return;
        let loginHash = CryptoHelper.createHashFromStringSha256(certificate.login)    
        const certificat_path = path.join(this.getCertificateFolderPath(), `.certif${loginHash}`);
        return CryptoHelper.encryptToFileWithUUID(certificat_path, certificate).catch((e) => {
            throw new Error("Unable to store Certificate : " + e.message)
        })
    }
    
    static async sendDeviceInfos(apikey, skipError=false) {
        let account;
        try {
            account = await Haapi.signOnWithApikey(ZAAP_CONFIG.ZAAP_GAME_ID, apikey);
        } catch (err) {
            if (!skipError || 1e3 === err.code) throw err;
            logger.error("[AuthHelper] cannot sign on with api key", err);
        }
        return Haapi.sendDeviceInfos(apikey, account.id, "ANKAMA", "STANDALONE", Device.getOsName(), "PC", null, Device.getUUID()).then(() => {
            logger.debug("[AuthHelper] device info sent")
        })
    }
}

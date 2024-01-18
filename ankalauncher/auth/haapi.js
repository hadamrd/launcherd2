import Http from '../common/http.js';
import logger from '../common/logger.js';
import ZAAP_CONFIG from "../common/zaapConfig.js";
import ZaapError from '../error/zaapError.js';
import AUTH_STATES from './auth.types.js';


const haapiUrl = "https://haapi.ankama.com/";


export default class Haapi {

    static getUrl(requestName, params) {
        let url = haapiUrl + {
            ANKAMA_ACCOUNT_ACCOUNT: "json/Ankama/v5/Account/Account",
            ANKAMA_ACCOUNT_CREATE_TOKEN: "json/Ankama/v5/Account/CreateToken",
            ANKAMA_ACCOUNT_ORIGIN_WITH_API_KEY: "json/Ankama/v5/Account/OriginWithApiKey",
            ANKAMA_ACCOUNT_SEND_DEVICE_INFOS: "json/Ankama/v5/Account/SendDeviceInfos",
            ANKAMA_ACCOUNT_SEND_MAIL_VALIDATION: "json/Ankama/v5/Account/SendMailValidation",
            ANKAMA_ACCOUNT_SET_EMAIL: "json/Ankama/v5/Account/SetEmail",
            ANKAMA_ACCOUNT_SET_NICKNAME_WITH_API_KEY: "json/Ankama/v5/Account/SetNicknameWithApiKey",
            ANKAMA_ACCOUNT_SIGN_ON_WITH_API_KEY: "json/Ankama/v5/Account/SignOnWithApiKey",
            ANKAMA_ACCOUNT_SET_IDENTITY_WITH_API_KEY: "json/Ankama/v5/Account/SetIdentityWithApiKey",
            ANKAMA_ACCOUNT_STATUS: "json/Ankama/v5/Account/Status",
            ANKAMA_API_CREATE_API_KEY: "json/Ankama/v5/Api/CreateApiKey",
            ANKAMA_API_DELETE_API_KEY: "json/Ankama/v5/Api/DeleteApiKey",
            ANKAMA_API_REFRESH_API_KEY: "json/Ankama/v5/Api/RefreshApiKey",
            ANKAMA_CMS_ITEMS_GET: "json/Ankama/v5/Cms/Items/Get",
            ANKAMA_CMS_ITEMS_CAROUSEL_GET: "json/Ankama/v5/Cms/Items/Carousel/GetForLauncher",
            ANKAMA_CMS_ITEMS_GETBYID: "json/Ankama/v5/Cms/Items/GetById",
            ANKAMA_CMS_POLLINGAME_GET: "json/Ankama/v5/Cms/PollInGame/Get",
            ANKAMA_CMS_POLLINGAME_MARKASREAD: "json/Ankama/v5/Cms/PollInGame/MarkAsRead",
            ANKAMA_GAME_END_SESSION_WITH_API_KEY: "json/Ankama/v5/Game/EndSessionWithApiKey",
            ANKAMA_GAME_LIST_WITH_API_KEY: "json/Ankama/v5/Game/ListWithApiKey",
            ANKAMA_GAME_SEND_EVENTS: "json/Ankama/v5/Game/SendEvents",
            ANKAMA_GAME_START_SESSION_WITH_API_KEY: "json/Ankama/v5/Game/StartSessionWithApiKey",
            ANKAMA_LEGALS_SET_TOU_VERSION: "json/Ankama/v5/Legals/SetTouVersion",
            ANKAMA_LEGALS_TOU: "json/Ankama/v5/Legals/Tou",
            ANKAMA_MONEY_OGRINS_AMOUNT: "json/Ankama/v5/Money/OgrinsAmount",
            ANKAMA_PREMIUM_GAME_CONNECT: "json/Ankama/v5/Game/Premium/Session/Connect",
            ANKAMA_PREMIUM_GAME_DISCONNECT: "json/Ankama/v5/Game/Premium/Session/Disconnect",
            ANKAMA_PROVIDER_API_KEY_LINK: "json/Ankama/v5/Provider/ApiKeyLink",
            ANKAMA_PROVIDER_API_KEY_LOGIN: "json/Ankama/v5/Provider/ApiKeyLogin",
            ANKAMA_PROVIDER_GHOST_CREATE: "json/Ankama/v5/Provider/ApiKeyGhostCreate",
            ANKAMA_SHIELD_SECURITY_CODE: "json/Ankama/v5/Shield/SecurityCode",
            ANKAMA_SHIELD_VALIDATE_CODE: "json/Ankama/v5/Shield/ValidateCode",
            ANKAMA_SHOP_ARTICLES_LIST_BY_CATEGORY: "json/Ankama/v5/Shop/ArticlesListByCategory",
            ANKAMA_SHOP_CATEGORIES_LIST: "json/Ankama/v5/Shop/CategoriesList",
            ANKAMA_SHOP_SIMPLE_BUY: "json/Ankama/v5/Shop/SimpleBuy",
            ANKAMA_SHOP_ARTICLE_LIST_BY_ID: "json/Ankama/v5/Shop/ArticlesListByIds",
            ANKAMA_VOD_ACCESS_TOKEN_GET: "json/Ankama/v5/Vod/AccessToken/GetAccessToken"
        }[requestName];
        const s = new URLSearchParams(params).toString();
        return s && (url += "?" + s), url
    }

    /**
     * Get the token for the given game
     * @param {int} gameId 
     * @param {{key: string}} apiCreds 
     * @param {string} certId
     * @param {string} certHash 
     * @returns {string} token
     */
    static async createToken(gameId, apiCreds, certId, certHash) {
        let getTokenUrl = this.getUrl("ANKAMA_ACCOUNT_CREATE_TOKEN", {
            game: gameId,
            certificate_id: certId,
            certificate_hash: certHash
        });
        return (await Http.get(getTokenUrl, { APIKEY: apiCreds.key })).body.token;
    }

    /**
     * Create a HAAPI API key for the given account
     * @param {string} login 
     * @param {string} password 
     * @param {string} certId 
     * @param {string} certHash 
     * @returns {Promise<{key: string, accountId: string, refreshToken: string, security: 'SECURED' | 'UNSECURED', reason: string, expirationDate: string}>
     */
    static async createApikey(login, password, certId = null, certHash = null) {
        let url = this.getUrl("ANKAMA_API_CREATE_API_KEY");
        let reqBody = {
            login: login,
            password: password,
            game_id: ZAAP_CONFIG.ZAAP_GAME_ID,
            long_life_token: true,
            shop_key: ZAAP_CONFIG.SHOP_HAAPI_KEYS.SHOP_KEY,
            payment_mode: ZAAP_CONFIG.SHOP_HAAPI_KEYS.PAYMENT_MODE,
            lang: "fr"
        }
        if (certId && certHash) {
            reqBody.certificate_id = certId;
            reqBody.certificate_hash = certHash;
        }
        try {
            const {
                body: body
            } = await Http.post(url, reqBody);
            return {
                key: body.key,
                accountId: body.account_id,
                refreshToken: body.refresh_token,
                security: body.data && body.data.security_state,
                reason: body.data && body.data.security_detail,
                expirationDate: body.expiration_date
            }
        } catch (e) {
            console.error(e)
            if (e.body && e.body.reason)
                throw new ZaapError({
                    codeError: "haapi." + e.body.reason,
                    error: e
                });
            throw 403 === e.statusCode && new ZaapError({
                error: e
            })
        }
    }

    /**
     * Sign on with an API key
     * @param {int} gameId
     * @param { key: string } apiCreds
     */
    static async signOnWithApikey(gameId, apiCreds) {
        let url = this.getUrl("ANKAMA_ACCOUNT_SIGN_ON_WITH_API_KEY");
        let reqBody = { game: gameId }
        const {
            body: body
        } = await Http.post(url, reqBody, {
            APIKEY: apiCreds.key, 
            "content-type": "text/plain;charset=UTF-8"
        });
        if (body.account.locked === ZAAP_CONFIG.USER_ACCOUNT_LOCKED.MAILNOVALID) {
            logger.error("[AUTH] Mail not confirmed by user")
            throw Error(AUTH_STATES.USER_EMAIL_INVALID);
        }
        return {
            id: body.id.toString(),
            account: this.parseAccount(body.account)
        }
    }

    /**
     * @param {{key: string}} apiKey
     */
    static async refreshApikey(apiKey) {
        let url = this.getUrl("ANKAMA_API_REFRESH_API_KEY");
        return Http.post(url, {
            refresh_token: apiKey.refreshToken,
            long_life_token: true
        }, {
            APIKEY: apiKey.key
        }).then((resp) => {
            return {
                key: resp.body.key,
                accountId: resp.body.account_id,
                refreshToken: resp.body.refresh_token
            }
        })
    }

    /**
     * Delete an API key
     * @param {{key: string}} apiCreds
     * @returns {Promise<boolean>}
     */
    static async deleteApikey(apiCreds) {
        let url = this.getUrl("ANKAMA_API_DELETE_API_KEY");
        return Http.get(url, {
            APIKEY: apiCreds.key
        }).then(() => true)
    }

    /**
     * Ask for a security code
     * @param {{key: string}} apiCreds 
     * @param {string} bySMS 
     * @returns {Promise<string>} The domain to use for the security code
     * @throws {ZaapError} If something went wrong
     * @throws {HttpError} If the request failed
     */
    static async shieldSecurityCode(apiCreds, bySMS) {
        let url = this.getUrl("ANKAMA_SHIELD_SECURITY_CODE", {
            transportType: bySMS ? "SMS" : "EMAIL"
        });
        return Http.get(url, { APIKEY: apiCreds.key }).then(resp => resp.body.domain)
    }

    /**
     * Validate a security code and get the certificate
     * @param {{key: string}} apiCreds
     * @param {string} shieldValidateCode
     * @param {string} hm1
     * @param {string} hm2
     * @returns {Promise<{id: string, certificateEncoding: string}>}
     * @throws {ZaapError}
     */
    static async shieldValidateCode(apiCreds, validationCode, hm1, hm2) {
        let userName = "launcher-Merkator";
        console.log("asking security code with username : " + userName)
        let url = this.getUrl("ANKAMA_SHIELD_VALIDATE_CODE", {
            game_id: ZAAP_CONFIG.ZAAP_GAME_ID,
            code: validationCode,
            hm1: hm1,
            hm2: hm2,
            name: userName
        });
        try {
            return (await Http.get(url, { APIKEY: apiCreds.key })).body
        } catch (e) {
            if (e && e.body && e.body.message) {
                if (e.body.message === "ALREADYSECURED") {
                    throw Error("ALREADYSECURED")
                }
                throw new ZaapError({
                    codeError: "haapi." + e.body.message,
                    error: e
                })
            }
            throw new ZaapError({
                codeError: "haapi.CODEPROBLEM",
                complement: e
            })
        }
    }

    static sendDeviceInfos(apikey, sessionId, connectionType, clientType, os, device, partner, deviceUUID) {
        let url = this.getUrl("ANKAMA_ACCOUNT_SEND_DEVICE_INFOS");
        return Http.post(url, {
            session_id: sessionId,
            connection_type: connectionType,
            client_type: clientType,
            os: os,
            device: device,
            partner: partner,
            device_uid: deviceUUID
        }, {
            APIKEY: apikey.key
        })
    }

    static parseAccount(body) {
        const {
            id: t,
            type: n,
            login: r,
            nickname: i,
            firstname: o,
            lastname: s,
            tag: a,
            security: c,
            added_date: u,
            locked: l,
            parent_email_status: p,
            avatar_url: h
        } = body;
        return {
            id: t,
            type: n,
            login: r,
            nickname: i,
            firstname: o,
            lastname: s,
            nicknameWithTag: `${i}#${a}`,
            tag: a,
            security: c,
            addedDate: u,
            locked: l,
            parentEmailStatus: p,
            avatar: h
        }
    }
}
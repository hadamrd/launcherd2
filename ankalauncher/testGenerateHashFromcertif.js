// let login = "d50055cd-5e09-4d1a-b799-654f99105eb2@mailslurp.com"
// let password = "rMrTXHA4*";
// const apikey = await Haapi.createApikey(login, password);
// console.log(apikey.key)
// await Haapi.shieldSecurityCode(apikey)
import nodecrypto from "crypto"

function makeid(length) {
    var result = '';
    var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for (var i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateHashFromCertif(cert, hm1, hm2) {
    console.log("generateHashFromCertif", cert, hm1, hm2);
    let cipher = nodecrypto.createDecipheriv("aes-256-ecb", hm2, "");
    let s = Buffer.concat([cipher.update(cert.encodedCertificate, "base64"), cipher.final()]);
    return nodecrypto.createHash("sha256").update(hm1 + s.toString()).digest("hex");
}
let cert = {
    id: 201461215,
    encodedCertificate: 'DudGaGOLYBS6dbXJ49Enkt/YkL9LKib1YaZyPX9B2osCyN287ZeTyc6CCrfi7noa8BnsBk2QJclu54Ughg8bCJkKq0mVsdYm2OKLCIakBeDrZfP0WcvnPr8k4oCS01h/23Fc6syH9zyIvVAAZHjA+M+QXB3p1Q2+I4n+hYL4WHl/T44fysFNZk93uxWimt3V0LnNpZGOoMTxnAyi+NFzu9l6HnRAFbDCmjcWMkGebCl9VIPTPwKkXmh00ExCZnOVAJz4tTAwwsf1UPaQjVtgaOyDCroTO/2ulyhhK/ddxo30mcmHXJpQFXA2bFdw7q9t1UD4WEnsAvpiAGQlrjtxknbxNU/sm1UUEZmW9DrMlz67tc5jjpNK7rHk5FKKbNC7AWHqNlerrIWfDal3ZUp14xf5XQcECJmKjMy4C8XmCf1c921Ktr6FZuR3kC2HKRcHW3r2Hiv1axtMuv1qmo4fPRl0ab+DhoiLoQ/40Mbhy+snUeBa5zjHRMa+a35LujactTxm0qPMZxNHrGBSoKxAmHGqefzDfZhRSStEWqu1Fsbn7Zc74bgB/3SzxSSGKJsTvp3MEkMjZPdx+xS2cA5iVg8bIDoHOGU2HgNl5IMwlj7H0MFeLBHLxI6MrcZqPR85GhVnVoPG5iqVzcMzI3bwGDWM5AxgoXdT/C7fssOw3GrddGklJrzp28zVcDBwQ+NpcgjpmmdFHdpYtdSsO7FLRnkctksBSYGE031wlMzn8PKIm8BAxajnfSmeadAitGNUPCg4M3BvlxAtHnNsiE4cGkUrhjDfnZ+C9uZvuxWx/A7ZPOmSTwhFEMIEYbZC+mdkaPg6AWgdEYEDn/J7a1jy/iOAmaMwqWsvRy/E6cYv51cmWniPlcywJ4Sc4GgkEdmGB41TeCMfzxx26Z83aGGgag=='
}
let hm1 = "ZRM6b3L7eLc9wa29AO5MjnKo33o2bMy8"
let hm2 = "WqH2UkRlVDtHaepzLtI7qogPGLzFW9Tj"

let r = generateHashFromCertif(cert, hm1, hm2)
console.log(r)
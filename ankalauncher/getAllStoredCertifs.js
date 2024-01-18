import fs from "fs-extra";
import path from "path";
import AuthHelper from "./auth/authHelper.js";

let certs_outputFilePath = path.join(process.cwd(), "certs.json");
let apikeys_outputFilePath = path.join(process.cwd(), "apikeys.json");

AuthHelper.getAllDecipheredStoredCertificates().then((certs) => {
    console.log("Result :", certs);
    fs.outputJSON(certs_outputFilePath, certs);
});

AuthHelper.getAllDecipheredStoredApiKeys().then((apikeys) => {
    console.log("Result :", apikeys);
    fs.outputJSON(apikeys_outputFilePath, apikeys);
});

import { codeErrors } from "./errorsCodes.js";
// import logger from "../common/logger";

export default class ZaapError extends Error {
    constructor({
        codeError: codeError = "",
        error: error = null,
        displayMessageOnFront: displayMessageOnFront = true,
        complement: complement = {}
    }) {
        super();
        Error.captureStackTrace(this, ZaapError); 
        if (error) {
            const nonFunctionProps = Object.getOwnPropertyNames(error).filter(() => "function" != typeof codeError[error]);
            for (const prop of nonFunctionProps) 
                this[prop] = error[prop];
            this.errorMessage = this.message;
            this.errorCode = this.code;
        }
        const {
            code: code,
            message: message
        } = serializeError(codeError);
        this.code = code || this.errorCode;
        this.message = message || this.errorMessage;
        this.displayMessageOnFront = displayMessageOnFront;
        this.complement = complement;
        this.codeErr = codeError.split(".").slice(-1);
        // logger.error("[AppError] \n" + this.toString())
    }
    toJSON() {
        return {
            code: this.code,
            message: this.message,
        }
    }
    toString() {
        return JSON.stringify({
            code: this.code,
            message: this.message
        })
    }
}

function serializeError(codeError) {
    let t = null;
    return codeError.split(".").forEach(e => {
        t = t ? t[e] : codeErrors[e.toLowerCase()];
    }), t || {}
}
 
export const getCode = e => serializeError(e).code

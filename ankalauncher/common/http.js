// import fetch from 'electron-fetch';
import puppeteer from "puppeteer";
class HttpError {
    constructor(response, body) {
        Error.captureStackTrace(this, this.constructor), 
        this.statusCode = response.status, 
        this.message = "Http request failed", 
        this.body = body
    }
}

export default class Http {

    static async request(url, req) {
        const browser = await puppeteer.launch();
        const page = await browser.newPage();
        await page.setRequestInterception(true);
        page.on('request', request => {
          const headers = {
            ...req.headers,
            "User-Agent": 'Zaap 3.9.3',
            "accept": "*/*",
            "accept-encoding": "gzip,deflate"
          };
          const postData = new URLSearchParams(req.body).toString();
          request.continue({ headers, postData, method: req.method });
        });
        // Navigate to the URL and get the response
        console.log(req)
        const response = await page.goto(url);
        console.info("[HTTP] request", req.method, url);
        let textResponse = await response.text();
        console.info("[HTTP] result", req.method, url, response.status(), response.statusText(), textResponse);
        const jsonContent = (204 !== response.status()) && response.headers() && response.headers()["content-type"] && response.headers()["content-type"] === "application/json";
        if (jsonContent) textResponse = JSON.parse(textResponse);
        if(response.status() >= 400)
            throw new HttpError(response, textResponse);
        await browser.close();
        return {body : textResponse};
    }

    static get(url, headers = {}) {
        return this.request(url, {
            method: "GET",
            headers: headers
        })
    }

    static post(url, data, headers = {}) {
        return this.request(url, {
            method: "POST",
            body: data,
            headers: headers
        })
    }

    static put(url, data, headers = {}) {
        const isJson = Object.prototype.hasOwnProperty.call(headers, "Content-Type") && "application/json" === headers["Content-Type"];
        return this.request(url, {
            method: "PUT",
            body: isJson ? JSON.stringify(data) : new URLSearchParams(data),
            headers: headers
        })
    }
    static delete(url, headers = {}) {
        return this.request(url, {
            method: "DELETE",
            headers: headers
        })
    }
}


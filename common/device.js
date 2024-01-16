const osPlatform = process.platform;
import child_process from 'child_process';
import nodecrypto from 'crypto';
import os from 'os';

let __uiid = null;
export default class Device {

    static getOsName() {
        return {
            win32: "WINDOWS",
            darwin: "MACOS",
            linux: "LINUX"
        } [osPlatform]
    }
    
    static async getUUID() {
        if (__uiid)
            return Promise.resolve(__uiid);
        return Device.machineId().then((id) => {
            __uiid = [os.platform(), os.arch(), id, os.cpus().length, os.cpus()[0].model].join();
            return __uiid;
        });
    }

    static getComputerRam() {
        return Math.pow(2, Math.round(Math.log(os.totalmem() / 1024 / 1024) / Math.log(2)))
    }

    static getOsVersion() {
        var t, n;
        [t, n] = os.release().split(".");
        return parseFloat(`${t}.${n}`)
    }

    static getGuuidCmdPerPltf(plt) {
        let mapper = {
            darwin: "ioreg -rd1 -c IOPlatformExpertDevice",
            win32: {
                native: "%windir%\\System32",
                mixed: "%windir%\\sysnative\\cmd.exe /c %windir%\\System32"
            }["win32" !== process.platform ? "" : "ia32" === process.arch && Object.prototype.hasOwnProperty.call(process.env, "PROCESSOR_ARCHITEW6432") ? "mixed" : "native"] + "\\REG.exe QUERY HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid",
            linux: "( cat /var/lib/dbus/machine-id /etc/machine-id 2> /dev/null || hostname ) | head -n 1 || :",
            freebsd: "kenv -q smbios.system.uuid || sysctl -n kern.hostuuid"
        };
        return mapper[plt];
    }

    static hashWithSha256(str) {
        return nodecrypto.createHash("sha256").update(str).digest("hex");
    }

    static parseMachineGuuid(stdOut) {
        switch (process.platform) {
            case "darwin":
                // eslint-disable-next-line no-useless-escape
                return stdOut.split("IOPlatformUUID")[1].split("\n")[0].replace(/\=|\s+|\"/gi, "").toLowerCase();
            case "win32":
                return stdOut.toString().split("REG_SZ")[1].replace(/\r+|\n+|\s+/gi, "").toLowerCase();
            case "linux":
            case "freebsd":
                return stdOut.toString().replace(/\r+|\n+|\s+/gi, "").toLowerCase();
            default:
                throw new Error("Unsupported platform: " + process.platform);
        }
    }

    static async machineId(withSha256Hash) {
        return new Promise((resolve, reject) => {
            child_process.exec(this.getGuuidCmdPerPltf(osPlatform), {}, (err, stdout, stderr) => {
                if (stderr && stderr.length > 0)
                    reject("Error while obtaining machine id: " + stderr.toString());
                if (err)
                    reject("Error while obtaining machine id: " + err.stack);
                var machineGuuid = this.parseMachineGuuid(stdout.toString());
                resolve(withSha256Hash ? machineGuuid : this.hashWithSha256(machineGuuid));
            });
        });
    }

    static machineIdSync(withSha256Hash) {
        var machineGuuid = this.parseMachineGuuid(child_process.execSync(this.getGuuidCmdPerPltf(osPlatform)).toString());
        return withSha256Hash ? machineGuuid : this.hashWithSha256(machineGuuid);
    }


}
import math
import platform
import subprocess
import hashlib
import os
import re

class Device:
    __uuid = None

    @staticmethod
    def get_os_name():
        os_name_map = {
            "Windows": "WINDOWS",
            "Darwin": "MACOS",
            "Linux": "LINUX"
        }
        return os_name_map.get(platform.system())

    @staticmethod
    def get_uuid():
        if Device.__uuid:
            return Device.__uuid

        id = Device.machine_id()
        Device.__uuid = "-".join([platform.system(), platform.machine(), id, str(len(os.sched_getaffinity(0))), platform.processor()])
        return Device.__uuid

    @staticmethod
    def get_computer_ram():
        return int(2 ** round(math.log(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / 1024**2, 2)))

    @staticmethod
    def get_os_version():
        return float('.'.join(platform.release().split(".")[:2]))

    @staticmethod
    def get_uuid_cmd_per_platform(plt):
        mapper = {
            "Darwin": "ioreg -rd1 -c IOPlatformExpertDevice",
            "Windows": "wmic csproduct get uuid",
            "Linux": "( cat /var/lib/dbus/machine-id /etc/machine-id 2> /dev/null || hostname ) | head -n 1 || :",
            "FreeBSD": "kenv -q smbios.system.uuid || sysctl -n kern.hostuuid"
        }
        return mapper.get(plt, "")

    @staticmethod
    def hash_with_sha256(string):
        return hashlib.sha256(string.encode()).hexdigest()

    @staticmethod
    def parse_machine_uuid(std_out, plt):
        if plt == "Darwin":
            return re.search(r"IOPlatformUUID\" = \"([^\"]+)\"", std_out).groups()[0].lower()
        elif plt == "Windows":
            return std_out.strip().lower()
        elif plt in ["Linux", "FreeBSD"]:
            return std_out.strip().lower()
        else:
            raise ValueError("Unsupported platform: " + plt)

    @staticmethod
    def machine_id(with_sha256_hash=False):
        plt = platform.system()
        cmd = Device.get_uuid_cmd_per_platform(plt)
        try:
            output = subprocess.check_output(cmd, shell=True, text=True)
            machine_uuid = Device.parse_machine_uuid(output, plt)
            return Device.hash_with_sha256(machine_uuid) if with_sha256_hash else machine_uuid
        except subprocess.CalledProcessError as e:
            raise Exception("Error while obtaining machine id: " + str(e))



if __name__ == "__main__":
    machine_id = Device.get_uuid()
    print(machine_id)
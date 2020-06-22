import re
import os
import sys
import base64
import hashlib
import warnings
import traceback
from binascii import unhexlify
from Crypto.Cipher import AES

warnings.filterwarnings("ignore")

BUILD_ID = "1.1.0"

runid = hashlib.sha1(os.urandom(16)).hexdigest()

READMES = [
    "MAPO-Readme.txt",
    "DETO-README.txt",
    "MBIT-INFO.txt",
    "DANTE-INFO.txt",
    "EDAB-README.txt",
    "GOMER-README.txt",
]
EXTENSIONS = [".mapo", ".deto", ".mbit", ".dante", ".edab", ".edab1", ".gomer"]
VERSIONS = {
    "Key verify": "=+ Key verify =+\n((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)",
    "L2 Protection": "~ L2 Protection ~\n((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)",
    "EDAB": "~ EDAB ~\n((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)",
    "GOMER": "~ GOMER ~\n((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)",
}


def print_banner():
    log(r" _____  ___________ ___________ _        _           ")
    log(r"/  __ \|  ___| ___ \_   _| ___ \ |      \ \          ")
    log(r"| /  \/| |__ | |_/ / | | | |_/ / |       \ \         ")
    log(r"| |    |  __||    /  | | |  __/| |        > >        ")
    log(r"| \__/\| |___| |\ \  | |_| |   | |____   / /  ______ ")
    log(r" \____/\____/\_| \_| \_(_)_|   \_____/  /_/  |______|")
    log("")


def log(text):
    print(text)
    try:
        with open("log.txt", "ab") as logfile:
            logfile.write((text + "\n").encode("utf-8"))
    except Exception as e:
        pass


def get_jumper(size):
    if size < 66560:
        return 0
    if size < 0x80000:
        return 0x40000
    if size < 0x100000:
        return 0x80000
    if size < 0x400000:
        return 0x100000
    if size < 0x2000000:
        return 0x200000
    if size < 0x4000000:
        return 0x400000
    if size < 0x20000000:
        return 0x800000
    if size < 0x40000000:
        return 0x1000000
    if size >= 0x280000000:
        return 0x20000000
    return 0x8000000


def unpad(text):
    val = text[-1]
    if val == 0:
        val = 16
    pad = text[-val:]
    if val > 16 or not all(c == pad[0] for c in pad):
        return None

    return text[:-val]


def decrypt_data(aeskey, data):
    aes = AES.new(aeskey, AES.MODE_CBC, b"\x00" * 16)
    plain = unpad(aes.decrypt(data))
    return plain


def transform_name(path, exts):
    for ext in exts:
        if ext in path:
            return path[: path.rfind(ext)]


def get_encrypted_files(encrypted_extensions):
    if sys.platform == "linux" or sys.platform == "linux2":
        for file in get_encrypted_files_from(".", encrypted_extensions):
            yield file
    elif sys.platform == "win32" or sys.platform == "cygwin":
        import win32api

        for drive in win32api.GetLogicalDriveStrings().split("\x00")[:-1]:
            log("[-] Scanning drive " + drive)
            for file in get_encrypted_files_from(drive, encrypted_extensions):
                yield file
    else:
        log("[!] Sorry, system not supported!")


def get_encrypted_files_from(rootdir, encrypted_extensions):
    for root, subdirs, files in os.walk(rootdir):
        for filename in files:
            ext = os.path.splitext(filename)[1]
            if ext in encrypted_extensions:
                yield os.path.join(root, filename)


def decrypt_files_with_key(files, key, exts):
    for path in files:
        try:
            log("[-] Decrypting file: " + path)

            orig_name = transform_name(path, exts)

            aes = AES.new(key, AES.MODE_CBC, b"\x00" * 16)

            fsize = os.path.getsize(path)
            jumper = get_jumper(fsize)

            with open(path, "rb") as encfile, open(orig_name, "wb") as outfile:
                while True:
                    encrypted_chunk = encfile.read(0x10000)
                    chunk = aes.decrypt(encrypted_chunk)
                    if len(encrypted_chunk) < 0x10000:
                        chunk = unpad(chunk)
                        outfile.write(chunk)
                        break
                    outfile.write(chunk)
                    noncrypted_chunk = encfile.read(jumper)
                    if len(noncrypted_chunk) < jumper:
                        encrypted_chunk = noncrypted_chunk
                        chunk = aes.decrypt(encrypted_chunk)
                        chunk = unpad(chunk)
                        outfile.write(chunk)
                        break
                    outfile.write(noncrypted_chunk)
            log("[*] Decrypted file: " + orig_name)
        except Exception as e:
            log("[!] Exception: " + traceback.format_exc())


def find_ransom_note(rootdir):
    for root, subdirs, files in os.walk(rootdir):
        for filename in files:
            if filename in READMES:
                yield os.path.join(root, filename)


def get_ransom_note():
    if sys.platform == "linux" or sys.platform == "linux2":
        for file in find_ransom_note("."):
            yield file
    elif sys.platform == "win32" or sys.platform == "cygwin":
        import win32api

        for drive in win32api.GetLogicalDriveStrings().split("\x00")[:-1]:
            log("[-] Scanning drive " + drive)
            for file in find_ransom_note(drive):
                yield file
    else:
        log("[!] Sorry, system not supported!")


def validate_key(key, note_path):
    with open(note_path, "r") as f:
        ransom_note = f.read()

    log(
        "[-] Ransom note contents: "
        + base64.b64encode(ransom_note.encode("utf-8")).decode("utf-8")
    )

    for version, regex in VERSIONS.items():
        encrypted_test = re.findall(regex, ransom_note)
        if not encrypted_test:
            continue

        log("[-] Encrypted test: " + repr(encrypted_test))

        data = base64.b64decode(encrypted_test[0])
        decrypted = decrypt_data(key, data)
        if not decrypted or decrypted != version.encode():
            return False
        return True
    return None


def main_decryptor():
    print_banner()
    log("[-] Initializing, execution ID " + runid)

    log("[+] Decryptor version {}".format(BUILD_ID))

    log("[-] searching for encrypted files")
    all_files = list(get_encrypted_files(EXTENSIONS))

    if not all_files:
        log("[!] No encrypted files found. Are you sure you're infected?")
        return

    log("[+] Found encrypted files:")
    for file in all_files:
        log("[-]    " + file)

    log("[-] locating ransom note")
    ransom_note = next(get_ransom_note(), None)

    if not ransom_note:
        log("[!] Couldn't find the ransom note. Are you sure you're infected?")
        return

    log("[+] Ransom note found at " + repr(ransom_note))

    key = input("Input the recovered key: ")
    log("[-] key inputted " + str(key))
    derived_key = unhexlify(key)

    if not validate_key(derived_key, ransom_note):
        log(
            "[!] Couldn't validate the recovered key. Either the key is incorrect or the ransomnote is corrupted"
        )
        return

    log("[-] Initiating decryption")
    decrypt_files_with_key(all_files, derived_key, EXTENSIONS)


def main():
    try:
        main_decryptor()
    except:
        log(traceback.format_exc())

    log("[-] Finishing")
    log(
        "[+] In case of any inquieries, please email cert@cert.pl and attach generated log.txt file!"
    )
    log("[-] Press 'Enter' to exit...")
    input()


if __name__ == "__main__":
    main()

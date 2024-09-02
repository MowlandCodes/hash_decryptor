r"""
 _   _           _           ____                             _
| | | | __ _ ___| |__       |  _ \  ___  ___ _ __ _   _ _ __ | |_ ___  _ __
| |_| |/ _` / __| '_ \ _____| | | |/ _ \/ __| '__| | | | '_ \| __/ _ \| '__|
|  _  | (_| \__ \ | | |_____| |_| |  __/ (__| |  | |_| | |_) | || (_) | |
|_| |_|\__,_|___/_| |_|     |____/ \___|\___|_|   \__, | .__/ \__\___/|_|
                                                  |___/|_|

[*] Author : Mowland Production
[*] Github : https://github.com/XHadow_21
[*] Version : 1.0

Warning! This program is for educational purpose only...!

"""

import argparse
import hashlib
import itertools
import os.path
import string
import sys as _sys
import textwrap
import time


salt = string.digits

# Coloring
ERROR = "\x1b[31;1m"
WARNING = "\x1b[33;1m"
SUCCESS = "\x1b[32;1m"
INFO = "\x1b[34;1m"
NORMAL = "\x1b[0m"

def sha256_decrypt(hash_strings:str, wordfile:str):
    print(f"{WARNING}[*] Initializing....{NORMAL}\n")
    time.sleep(2)

    if args.decrypt_mode == "brute":
        for i in range(1, 20):
            for x in itertools.product(salt, repeat=i):
                SHA256 = hashlib.sha256()
                word = "".join(x)
                SHA256.update(word.encode())
                if hash_strings == SHA256.hexdigest():
                    print(f"\n{SUCCESS}[*]{NORMAL} {hash_strings} is Decrypted...")
                    print(f"{INFO}[*]{NORMAL} Decrypted string is ==> {INFO}{word}{NORMAL}")
                    exit(0)

                else:
                    print(f"{INFO}[*]{NORMAL} Attempting to decrypt {INFO}{hash_strings}{NORMAL} with --> {INFO}{SHA256.hexdigest()}{NORMAL} --> {word}")

    else:
        try:
            with open(wordfile, "r") as wordlist:
                for word in wordlist.readlines():
                    SHA256 = hashlib.sha256()
                    SHA256.update(word.rstrip("\n").encode())
                    if hash_strings == SHA256.hexdigest():
                        print(f"\n{SUCCESS}[*]{NORMAL} {hash_strings} is Decrypted...")
                        print(f"{INFO}[*]{NORMAL} Decrypted string is ==> {INFO}{word.rstrip("\n")}{NORMAL}")
                        exit(0)

                    else:
                        print(f"{INFO}[*]{NORMAL} Attempting to decrypt {INFO}{hash_strings}{NORMAL} with --> {INFO}{SHA256.hexdigest()}{NORMAL} --> {word.rstrip("\n")}")

        except FileNotFoundError:
            print(f"{ERROR}[*]{NORMAL} The specified path is not found...!")

def sha1_decrypt(hash_strings:str, wordfile:str):
    print(f"{WARNING}[*] Initializing....{NORMAL}\n")
    time.sleep(3)

    if args.decrypt_mode == "brute":
        for i in range(1, 20):
            for x in itertools.product(salt, repeat=i):
                SHA1 = hashlib.sha1()
                SHA1.update(("".join(x)).encode())
                if hash_strings == SHA1.hexdigest():
                    print(f"\n{SUCCESS}[*]{NORMAL} {hash_strings} is Decrypted...")
                    print(f"{INFO}[*]{NORMAL} Decrypted string is ==> {INFO}{"".join(x)}{NORMAL}")
                    exit(0)

                else:
                    print(f"{INFO}[*]{NORMAL} Attempting to decrypt hash with string --> {INFO}{"".join(x)}{NORMAL}")

    else:
        try:
            with open(wordfile, "r") as wordlist:
                for word in wordlist.readlines():
                    SHA1 = hashlib.sha1()
                    SHA1.update(word.rstrip("\n").encode())
                    if hash_strings == SHA1.hexdigest():
                        print(f"\n{SUCCESS}[*]{NORMAL} {hash_strings} is Decrypted...")
                        print(f"{INFO}[*]{NORMAL} Decrypted string is ==> {INFO}{word.rstrip("\n")}{NORMAL}")
                        exit(0)

                    else:
                        print(f"{INFO}[*]{NORMAL} Attempting to decrypt hash with string --> {INFO}{word.rstrip("\n")}{NORMAL}")

        except FileNotFoundError:
            print(f"{ERROR}[*]{NORMAL} The specified path is not found...!")

def md5_decrypt(hash_strings:str, wordfile:str):
    print(f"{WARNING}[*] Initializing....{NORMAL}\n")
    time.sleep(3)

    if args.decrypt_mode == "brute":
        for i in range(1, 20):
            for x in itertools.product(salt, repeat=i):
                MD5 = hashlib.md5()
                MD5.update(("".join(x)).encode())
                if hash_strings ==  MD5.hexdigest():
                    print(f"\n{SUCCESS}[*]{NORMAL} {hash_strings} is Decrypted...")
                    print(f"{INFO}[*]{NORMAL} Decrypted string is ==> {INFO}{"".join(x)}{NORMAL}")
                    exit(0)

                else:
                    print(f"{INFO}[*]{NORMAL} Attempting to decrypt hash with string --> {INFO}{"".join(x)}{NORMAL}")

    else:
        try:
            with open(wordfile, "r") as wordlist:
                for word in wordlist.readlines():
                    MD5 = hashlib.md5()
                    MD5.update(word.rstrip("\n").encode())
                    if hash_strings ==  MD5.hexdigest():
                        print(f"\n{SUCCESS}[*]{NORMAL} {hash_strings} is Decrypted...")
                        print(f"{INFO}[*]{NORMAL} Decrypted string is ==> {INFO}{word.rstrip("\n")}{NORMAL}")
                        exit(0)

                    else:
                        print(f"{INFO}[*]{NORMAL} Attempting to decrypt hash with string --> {INFO}{word.rstrip("\n")}{NORMAL}")

        except FileNotFoundError:
            print(f"{ERROR}[*]{NORMAL} The specified path is not found...!")


def main():
    parser = argparse.ArgumentParser(prog=os.path.basename(__file__), formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent(fr"""
{INFO} _   _           _           ____                             _
| | | | __ _ ___| |__       |  _ \  ___  ___ _ __ _   _ _ __ | |_ ___  _ __
| |_| |/ _` / __| '_ \ _____| | | |/ _ \/ __| '__| | | | '_ \| __/ _ \| '__|
|  _  | (_| \__ \ | | |_____| |_| |  __/ (__| |  | |_| | |_) | || (_) | |
|_| |_|\__,_|___/_| |_|     |____/ \___|\___|_|   \__, | .__/ \__\___/|_|
                                                  |___/|_|{NORMAL}

{INFO}[*]{NORMAL} Author : Mowland Production
{INFO}[*]{NORMAL} Github : https://github.com/XHadow_21
{INFO}[*]{NORMAL} Version : 1.0

{WARNING}Warning! This program is for educational purpose only...!{NORMAL}
"""))
    parser.add_argument("-ht", "--hash-type", required=True, choices=["sha256", "sha1", "md5"], dest="hash_type", type=str, help="Define Hash type to decrypt")
    parser.add_argument("-hv", "--hash-value", required=True, dest="hash_string", type=str, help="Hash string to decrypt")
    parser.add_argument("-m", "--mode", choices=["brute", "wordlist"], dest="decrypt_mode", help="Method to decrypt the hash", default="brute")
    parser.add_argument("-w", "--wordlist", dest="wordlist", help="Wordlist file", metavar="FILE", default=None)

    global args

    args = parser.parse_args()

    if (args.decrypt_mode == "wordlist") and (args.wordlist == "" or args.wordlist == None):
        parser.print_help()
        exit(1)

    match(args.hash_type, args.decrypt_mode):
        case("sha256", "brute"):
            sha256_decrypt(args.hash_string, "None")

        case("sha256", "wordlist"):
            sha256_decrypt(args.hash_string, args.wordlist)

        case("sha1", "brute"):
            sha1_decrypt(args.hash_string, "None")

        case("sha1", "wordlist"):
            sha1_decrypt(args.hash_string, args.wordlist)

        case("md5", "brute"):
            md5_decrypt(args.hash_string, "None")

        case("md5", "wordlist"):
            md5_decrypt(args.hash_string, args.wordlist)

        case _:
            parser.print_help()
            exit(1)

if __name__ == "__main__":
    main()


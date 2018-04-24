import argparse
import sys

from base64 import b64decode
from xml.dom import minidom
import json

from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def prefs_to_aes(prefs_key):
    # Split in two the key in the preferences and add the strange text here
    key = prefs_key[0:len(prefs_key) // 2]
    key += "a!k@ES2,g86AX&D8vn2]"
    key += prefs_key[len(prefs_key) // 2:]

    # Hash the text to a sha256 fingerprint -> resulting key always 256 bit
    key_hash = SHA256.new(data=bytes(key, 'utf-8'))

    return key_hash.digest()


def decrypt(value, key):
    cypher_text = b64decode_missing_padding(value)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(cypher_text)
    return decrypted.decode('utf-8')


def b64decode_missing_padding(string):
    pad = len(string) % 4
    string += "=" * pad
    return b64decode(string)


def parse_xml(file_path):
    """
    Parses the encrypted XML and returns a dict with the key value pairs
    :param file_path:
    :return:
    """

    xml_file = minidom.parse(file_path)
    tags = xml_file.getElementsByTagName("string")
    settings = {str(tag.getAttribute('name')): str(tag.firstChild.data) for tag in tags}

    return settings


def decrypt_dict(encrypted_dict):
    prefs_key_candidates = [value for key, value in encrypted_dict.items() if len(value) == 26]

    # print(prefs_key_candidates)
    settings_all = []
    for candidate in prefs_key_candidates:
        # Translate the AES Key
        prefs_enc_key = candidate
        aes_key = prefs_to_aes(prefs_enc_key)
        # print("AES KEY: %s \n" % aes_key)

        # Decrypt the actual content
        settings_decrypted = {decrypt(key, aes_key): decrypt(value, aes_key) for key, value in encrypted_dict.items()
                              if value not in prefs_key_candidates}

        settings_all.append(settings_decrypted)
    return settings_all


if __name__ == '__main__':
    module_description = "Decrypt preference files protected by the custom 'SecurePreferences' version for Swisscom InternetBox App and QBee App"

    parser = argparse.ArgumentParser(description=module_description)

    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')
    parser.add_argument('-t', '--type', choices=['s', 'o', 'l'],
                        help='Version of Secure Preferences used to encrypt the file: [s]wisscom/qbee, '
                             '[o]original (SecurePreferences > 0.4), [l]egacy (SecurePreferences <= 0.4)',
                        default='s')
    parser.add_argument('input', help='File to be analyzed (default: std input)', nargs='?',
                        type=argparse.FileType('r'),
                        default=sys.stdin)
    parser.add_argument('output', help='Result file (default: std output)', nargs='?', type=argparse.FileType('w'),
                        default=sys.stdout)

    args = parser.parse_args()

    if args.type == "s":
        settings_crypt = parse_xml(args.input)
        settings_clear = {
            'decrypted_settings': decrypt_dict(settings_crypt),
        }
        json.dump(settings_clear, args.output, indent=4)
    else:
        raise NotImplementedError(
            "Unfortunately this version only handles the custom settings format used by the QBee & Swisscom Home App for Android")

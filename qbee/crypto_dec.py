import argparse
import sys

from base64 import b64decode
from xml.dom import minidom
import json

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Padding


def prefs_to_aes(prefs_key):
    """Transforms the kex from the xml file to the final AES key, cf. decompilation of QBee apk.
    :param prefs_key: Key parsed from xml file as b64 encoded string
    :return: final aes key as byte string
    """
    # Split in two the key in the preferences and add the strange text here
    key = prefs_key[0:len(prefs_key) // 2]
    key += "a!k@ES2,g86AX&D8vn2]"
    key += prefs_key[len(prefs_key) // 2:]

    # Hash the text to a sha256 fingerprint -> resulting key always 256 bit
    key_hash = SHA256.new(data=key.encode('utf-8'))

    return key_hash.digest()


def decrypt(value, key):
    """Decrypts the given value using AES ECB with a blocksize of 16 bytes, removing padding as needed
    :param value: Encrypted string
    :type value: str
    :param key: AES Encryption Key
    :type key: bytes
    :return:
    """
    cypher_text = b64decode_missing_padding(value)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(cypher_text)
    decrypted = Padding.unpad(decrypted, 16)
    return decrypted.decode('utf-8')


def b64decode_missing_padding(string):
    """Decodes strings encoded in base64 but missing padding
    :param string: base64 encoded string with (possibly) missing padding
    :return: decoded string
    """
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
    """Decrypts a dict of preferences coming from an xml encrypted with the SecurePreferences library

    The values of the dict are filtered to found the possible AES keys, in the case of the custom format used by QBee
    and Swisscom those are base64 encoded strings of 26 char of length.

    :param encrypted_dict: Dictionary containing the encrypted key and values
    :return: List of dictionaries with only the decrypted key and values, one dictionary per possible decryption key.
    """
    prefs_key_candidates = [value for key, value in encrypted_dict.items() if len(value) == 26]

    settings_all = []
    for candidate in prefs_key_candidates:
        # Translate the AES Key
        aes_key = prefs_to_aes(candidate)

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

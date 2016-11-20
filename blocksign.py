import os
import argparse
import json
from configparser import SafeConfigParser
from pycoin.key.key_from_text import key_from_text
from pycoin.tx.Tx import TxOut
from pycoin.tx.tx_utils import (create_tx, sign_tx)
from pycoin.tx.pay_to import ScriptNulldata
from pycoin.services.insight import InsightProvider
from pycoin.key import Key
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import hashlib

try:
    from urllib2 import HTTPError, urlopen
    from urllib import urlencode
except ImportError:
    from urllib.request import urlopen

class InsightProvider(InsightProvider):
    def get_address(self, address):
        URL = "%s/api/addr/%s" % (self.base_url, address)
        r = json.loads(urlopen(URL).read().decode("utf8"))
        return type('', (object,), r)


explorer = InsightProvider('https://insight.bitpay.com')

config_filename = '.pyblocksign.ini'
config_path = os.path.join(os.environ['HOME'], config_filename)
config = None

salt = '#$%'
iv = 'This is an IV#$%'

fee = 1000


def password_to_key(password):
    return PBKDF2(str.encode(password), str.encode(salt))


def encrypt(str, password):
    aes = AES.new(password_to_key(password), AES.MODE_CFB, iv)
    return bytes.decode(base64.b64encode(aes.encrypt(str)))


def decrypt(str, password):
    aes = AES.new(password_to_key(password), AES.MODE_CFB, iv)
    return bytes.decode(aes.decrypt(base64.b64decode(str)))


def read_config():
    global config_path, config
    config = SafeConfigParser()
    if os.path.isfile(config_path):
            config.read(config_path)


def write_config():
    global config_path, config
    f = open(config_path, 'w')
    try:
        config.write(f)
    finally:
        f.close()


def decrypt_key():
    encrypted = config.get('Wallet', 'WIF')
    password = input('Password: ')
    wif = decrypt(encrypted, password)
    return key_from_text(wif), wif


def import_wif(args):
    global config
    while True:
        password = input('Password: ')
        repeat_password = input('Repeat password: ')
        if password == repeat_password:
            break
        print('Password don\'t match')
    encrypted = encrypt(args.wif, password)
    if not config.has_section('Wallet'):
        config.add_section('Wallet')
    config.set('Wallet', 'WIF', encrypted)
    write_config()


def show_address(args):
    key, wif = decrypt_key()
    pub_key = Key(public_pair=key.public_pair())
    addr = pub_key.address()
    data = explorer.get_address(addr)
    print()
    print('Address: ', data.addrStr)
    print('Balance: ', data.balanceSat)


def double_sha256(arr):
    h1 = hashlib.sha256(arr)
    h2 = hashlib.sha256()
    h2.update(h1.digest())
    return h2.digest()


def get_spendable(address):
    for out in explorer.spendables_for_address(address):
        if out.coin_value >= fee:
            return out


def file_signature(filename):
    file_hash = double_sha256(open(filename, 'rb').read())
    header = bytes([0x42, 0x53])
    with_header = header + file_hash
    checksum = double_sha256(with_header)[:4]
    return with_header + checksum, file_hash


def build_tx(signature, address, wif):
    prev = get_spendable(address)
    spend_tx = create_tx([prev], [address])
    signature_script = ScriptNulldata(signature).script()
    signature_out = TxOut(0, signature_script)
    spend_tx.txs_out.append(signature_out)
    sign_tx(spend_tx, wifs=[wif])
    return spend_tx


def sign_document(args):
    key, wif = decrypt_key()
    pub_key = Key(public_pair=key.public_pair())
    addr = pub_key.address()
    out = get_spendable(addr)
    if out is None:
        raise Exception('Insufficient funds')
    signature, file_hash = file_signature(args.filename)
    print('Signing document: ', args.filename)
    print('File hash: ', file_hash.hex())
    print('File signature: ', signature.hex())

    tx = build_tx(signature, addr, wif)
    print(tx.as_hex())


def verify_document(args):
    pass


def list_documents(args):
    pass


def main():
    read_config()
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    wif_parser = subparsers.add_parser('wif')
    wif_parser.add_argument('wif')
    wif_parser.set_defaults(func=import_wif)

    address_parser = subparsers.add_parser('address')
    address_parser.set_defaults(func=show_address)

    sign_parser = subparsers.add_parser('sign')
    sign_parser.add_argument('filename')
    sign_parser.set_defaults(func=sign_document)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()

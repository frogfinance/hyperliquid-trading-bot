from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import eth_account
from eth_account.signers.local import LocalAccount
import json
import os
import logging
from hyperliquid.exchange import Exchange
from hyperliquid.info import Info

from src import config


def decrypt_secret_key(encrypted_data: str, password: str) -> str:
    data = json.loads(encrypted_data)
    salt = base64.b64decode(data['salt'])
    nonce = base64.b64decode(data['nonce'])
    encrypted_key = base64.b64decode(data['encrypted_key'])

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    aesgcm = AESGCM(key)
    decrypted_key = aesgcm.decrypt(nonce, encrypted_key, None)
    
    return decrypted_key.decode()


def setup(base_url=None, skip_ws=False, encrypted_key=None):
    secret_key = encrypted_key
    
    account: LocalAccount = eth_account.Account.from_key(secret_key)
    
    address = account.address
    logging.info("Running with account address:", address)
    if address != account.address:
        logging.info("Running with agent address:", account.address)
    info = Info(base_url, skip_ws)
    user_state = info.user_state(address)
    margin_summary = user_state["marginSummary"]
    if float(margin_summary["accountValue"]) == 0:
        logging.info("Not running the example because the provided account has no equity.")
        url = info.base_url.split(".", 1)[1]
        error_string = f"No accountValue:\nIf you think this is a mistake, make sure that {address} has a balance on {url}.\nIf address shown is your API wallet address, update the config to specify the address of your account, not the address of the API wallet."
        raise Exception(error_string)
    exchange = Exchange(account, base_url, account_address=address)
    return address, info, exchange

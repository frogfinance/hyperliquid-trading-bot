import sqlite3
import json
import logging
import bcrypt
from eth_account import Account
from src import config

MASTER_ENCRYPTION_PASSWORD = config.SECRET_KEY


class WalletManager:
    def __init__(self, db_path="dbs/wallets.db"):
        """
        Initialize the wallet manager and create the database tables if they don't exist.
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.create_tables()
        logging.info("Initialized WalletManager with DB at '%s'", self.db_path)

    def create_tables(self):
        """
        Create the wallets tables.
        """
        cursor = self.conn.cursor()
        # Create table for wallets
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                wallet_address TEXT NOT NULL,
                encrypted_key TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        ''')
        self.conn.commit()
        logging.info("Wallet database table ensured.")


    def get_user_id(self, discord_id):
        """
        Retrieve the internal user id from the Discord ID.
        Returns the id or None if not found.
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id FROM users WHERE discord_id = ?
        ''', (discord_id,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None

    def create_user_wallet(self, user):
        """
        Generate a new Ethereum account for the given user, encrypt its private key, and store it.
        If the user does not exist, they will be created.
        Returns a tuple of (wallet_address, encrypted_key_json).
        """
        # Create a new Ethereum account
        account = Account.create()
        wallet_address = account.address
        private_key = account.privateKey

        # Encrypt the private key using the provided encryption password.
        # The encryption uses a keyfile JSON format that includes a random salt.
        encrypted_key = Account.encrypt(private_key, f"{user.password_hash}{user.salt}")
        encrypted_key_json = json.dumps(encrypted_key)

        user_id = user.id

        # Save the wallet details into the database
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO wallets (user_id, wallet_address, encrypted_key)
            VALUES (?, ?, ?)
        ''', (user_id, wallet_address, encrypted_key_json))
        self.conn.commit()
        wallet_id = cursor.lastrowid

        logging.info("Created wallet for user '%s': %s (wallet id: %s)", user.discord_id, wallet_address, wallet_id)
        return wallet_address, encrypted_key_json

    def get_user_wallet(self, discord_id):
        """
        Retrieve the wallet information for a given user (discord_id).
        Returns a dictionary with wallet_address and encrypted_key if exists, or None.
        """
        user_id = self.get_user_id(discord_id)
        if not user_id:
            logging.warning("No user found for discord_id '%s'.", discord_id)
            return None

        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT wallet_address, encrypted_key FROM wallets WHERE user_id = ?
        ''', (user_id,))
        result = cursor.fetchone()
        if result:
            wallet_address, encrypted_key_json = result
            return {
                "wallet_address": wallet_address,
                "encrypted_key": encrypted_key_json
            }
        else:
            logging.warning("No wallet found for user '%s'.", discord_id)
            return None

    def get_private_key(self, user, encrypted_key_json):
        """
        Retrieve and decrypt a user's private key.
        Returns the private key (in bytes) if successful, or None.
        """
        try:
            encrypted_key = json.loads(encrypted_key_json)
            # Decrypt the key using the provided encryption password
            private_key = Account.decrypt(encrypted_key, f"{user.password_hash}{user.salt}")
            logging.info("Decrypted private key for user '%s'", user.discord_id)
            return private_key
        except Exception as e:
            logging.error("Failed to decrypt private key for user '%s': %s", user.discord_id, e)
            return None

    def close(self):
        """
        Close the database connection.
        """
        self.conn.close()
        logging.info("Database connection closed.")

import logging
import sqlite3

import bcrypt

class DiscordUser():
    id = ''
    discord_id = ''
    password_hash = ''
    authorized = True
    salt = ''


class DiscordUserService():
    def __init__(self, db_path="dbs/users.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.create_tables()

    def create_tables(self):
        """
        Create the users and wallets tables.
        """
        cursor = self.conn.cursor()
        # Create table for users
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                discord_id TEXT UNIQUE NOT NULL,
                authorized INTEGER DEFAULT 0,
                channel_id TEXT,
                password_hash TEXT,
                salt TEXT
            );
        ''')
        self.conn.commit()
        logging.info("User database tables generated or skipped.")

    def check_if_user_exists(self, discord_id, channel_id):
        # Check if user exists
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM users WHERE discord_id = ? and channel_id = ?
                       ''', (discord_id, channel_id))
        result = cursor.fetchone()
        if result:
            return True
        return False
        
    def create_user(self, discord_id, channel_id, password):
        user = DiscordUser()
        user.discord_id = discord_id
        user.password_hash = self.hash_user_pw(password)
        user.authorized = True
        user.salt = bcrypt.gensalt().decode('utf-8')
        user.id = self.save_user(user)
        user.channel_id = channel_id
        return user

    def get_user(self, discord_id):
        # get user by discord_id from the database
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM users WHERE discord_id = ?
        ''', (discord_id,))
        result = cursor.fetchone()
        if result:
            user = DiscordUser()
            user.id = result[0]
            user.discord_id = result[1]
            user.authorized = bool(result[2])
            user.password_hash = result[3]
            user.salt = result[4]
            return user
        return None


    def save_user(self, user: DiscordUser):
        """
        Add a new user by their Discord ID.
        Returns the new user's internal id or the existing user's id.
        """
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (discord_id, authorized, password_hash, salt, channel_id ) VALUES (?, ?, ?, ?)
            ''', (user.discord_id, int(user.authorized), user.password_hash, user.salt, user.channel_id))
            self.conn.commit()
            user_id = cursor.lastrowid
            logging.info("Added user '%s' with id %s", self.discord_id, user_id)
            return user_id
        except sqlite3.IntegrityError:
            # User already exists; return its id
            cursor.execute('SELECT id FROM users WHERE discord_id = ?', (self.discord_id,))
            result = cursor.fetchone()
            logging.info("User '%s' already exists with id %s", self.discord_id, result[0])
            return result[0]

    def hash_user_pw(self, password: str):
        """
        Set (or update) the hashed password for a user.
        Uses bcrypt to hash the password.
        """
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        return hashed

    def verify_user_password(self, user: DiscordUser, password: str):
        """
        Verify a user's password. Returns True if the password matches, else False.
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT password_hash FROM users WHERE discord_id = ?
        ''', (user.discord_id,))
        result = cursor.fetchone()
        if result and result[0]:
            stored_hash = result[0].encode('utf-8')
            is_valid = bcrypt.checkpw(password.encode('utf-8'), stored_hash)
            logging.info("Password verification for user '%s': %s", user.discord_id, is_valid)
            return is_valid
        else:
            logging.warning("No password set for user '%s'", user.discord_id)
            return False

    def authorize_user(self, user: DiscordUser):
        """
        Mark a user as authorized to trade.
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE users SET authorized = 1 WHERE discord_id = ?
        ''', (user.discord_id,))
        self.conn.commit()
        logging.info("User '%s' has been authorized.", user.discord_id)
        user.authorized = True
        return user

    def deauthorize_user(self, user: DiscordUser):
        """
        Mark a user as unauthorized to trade.
        """
        user.authorized = False
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE users SET authorized = 0 WHERE discord_id = ?
        ''', (user.discord_id,))
        self.conn.commit()
        logging.info("User '%s' has been deauthorized.", user.discord_id)
        return user

    def is_authorized(self, user: DiscordUser):
        """
        Check if a user is authorized.
        Returns True if authorized, False otherwise.
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT authorized FROM users WHERE discord_id = ?
        ''', (user.discord_id,))
        result = cursor.fetchone()
        authorized = bool(result and result[0])
        logging.info("User '%s' authorization status: %s", user.discord_id, authorized)
        return authorized
    
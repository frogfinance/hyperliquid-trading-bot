import os
import json
import pytest
import factory
from faker import Faker

from src.wallet_manager import WalletManager

fake = Faker()


# A simple factory to generate fake Discord user data
class DiscordUserFactory(factory.Factory):
    class Meta:
        model = dict

    discord_id = factory.LazyAttribute(lambda _: fake.uuid4())
    password = factory.LazyAttribute(lambda _: fake.password())


@pytest.fixture
def temp_wallet_manager(tmp_path):
    """
    Create a WalletManager instance with a temporary SQLite database.
    The database file is stored in a temporary directory and removed after tests.
    """
    db_path = str(tmp_path / "wallets_test.db")
    wm = WalletManager(db_path=db_path)
    yield wm
    wm.close()
    if os.path.exists(db_path):
        os.remove(db_path)


def test_add_user_and_password(temp_wallet_manager):
    """
    Test that a user can be added, that their password is set correctly,
    and that password verification works.
    """
    user = DiscordUserFactory()
    discord_id = user["discord_id"]
    password = user["password"]

    # Set the user's password and verify it
    temp_wallet_manager.set_user_password(discord_id, password)
    assert temp_wallet_manager.verify_user_password(discord_id, password)
    # Test that a wrong password does not verify
    assert not temp_wallet_manager.verify_user_password(discord_id, "wrong_password")


def test_authorize_user(temp_wallet_manager):
    """
    Test adding a user and then authorizing them.
    """
    user = DiscordUserFactory()
    discord_id = user["discord_id"]

    # Add the user (initially not authorized)
    temp_wallet_manager.add_user(discord_id)
    assert not temp_wallet_manager.is_authorized(discord_id)

    # Authorize the user and check status
    temp_wallet_manager.authorize_user(discord_id)
    assert temp_wallet_manager.is_authorized(discord_id)


def test_create_and_retrieve_wallet(temp_wallet_manager):
    """
    Test that a wallet is created for a user and can be retrieved.
    """
    user = DiscordUserFactory()
    discord_id = user["discord_id"]

    # Create a wallet for the user
    wallet_address, encrypted_key = temp_wallet_manager.create_user_wallet(discord_id)

    # Retrieve the wallet data and check contents
    wallet_data = temp_wallet_manager.get_user_wallet(discord_id)
    assert wallet_data is not None
    assert wallet_data["wallet_address"] == wallet_address

    # Ensure the encrypted key is valid JSON and represents a dictionary
    key_dict = json.loads(wallet_data["encrypted_key"])
    assert isinstance(key_dict, dict)


def test_get_private_key(temp_wallet_manager):
    """
    Test that the private key can be decrypted and retrieved.
    """
    user = DiscordUserFactory()
    discord_id = user["discord_id"]

    # Create a wallet for the user
    wallet_address, encrypted_key = temp_wallet_manager.create_user_wallet(discord_id)

    # Retrieve the private key (should be bytes of length 32)
    private_key = temp_wallet_manager.get_private_key(discord_id)
    assert isinstance(private_key, bytes)
    assert len(private_key) == 32

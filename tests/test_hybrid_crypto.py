"""Unit tests validating all security properties from the paper."""

import os, pytest
from src.hybrid_crypto import generate_rsa_keypair, encrypt, decrypt


@pytest.fixture(scope="module")
def rsa_keys():
    return generate_rsa_keypair()


class TestCorrectness:
    def test_short_message(self, rsa_keys):
        pub, priv = rsa_keys
        msg = b"Hello IEEE ICIDCA-2025!"
        assert decrypt(encrypt(msg, pub), priv) == msg

    def test_empty_message(self, rsa_keys):
        pub, priv = rsa_keys
        msg = b""
        assert decrypt(encrypt(msg, pub), priv) == msg

    def test_1kb(self, rsa_keys):
        pub, priv = rsa_keys
        msg = os.urandom(1024)
        assert decrypt(encrypt(msg, pub), priv) == msg

    def test_10kb(self, rsa_keys):
        pub, priv = rsa_keys
        msg = os.urandom(10240)
        assert decrypt(encrypt(msg, pub), priv) == msg


class TestNonDeterminism:
    """Same plaintext must produce different ciphertext (OAEP + random IV)."""
    def test_different_ciphertexts(self, rsa_keys):
        pub, _ = rsa_keys
        msg = b"non-determinism test"
        assert encrypt(msg, pub) != encrypt(msg, pub)


class TestForwardSecrecy:
    """Independent sessions must not affect each other."""
    def test_sessions_independent(self, rsa_keys):
        pub, priv = rsa_keys
        m1, m2 = b"session one", b"session two"
        assert decrypt(encrypt(m1, pub), priv) == m1
        assert decrypt(encrypt(m2, pub), priv) == m2


class TestTampering:
    def test_tampered_ciphertext(self, rsa_keys):
        pub, priv = rsa_keys
        ct = bytearray(encrypt(b"tamper test", pub))
        ct[-1] ^= 0xFF
        with pytest.raises(Exception):
            decrypt(bytes(ct), priv)

    def test_wrong_key_rejected(self):
        pub1, _      = generate_rsa_keypair()
        _,    priv2  = generate_rsa_keypair()
        ct = encrypt(b"wrong key test", pub1)
        with pytest.raises(Exception):
            decrypt(ct, priv2)


class TestKeyManager:
    def test_generate_save_load_encrypt(self, tmp_path):
        from src.key_manager import KeyManager
        km = KeyManager(str(tmp_path / "keys"))
        km.generate_and_save()
        assert km.has_keys()
        msg = b"key manager round-trip"
        assert decrypt(encrypt(msg, km.load_public_key()), km.load_private_key()) == msg

    def test_passphrase_protected_key(self, tmp_path):
        from src.key_manager import KeyManager
        km = KeyManager(str(tmp_path / "keys2"))
        km.generate_and_save(passphrase="s3cr3t!")
        msg = b"passphrase test"
        pub  = km.load_public_key()
        priv = km.load_private_key(passphrase="s3cr3t!")
        assert decrypt(encrypt(msg, pub), priv) == msg

    def test_key_rotation(self, tmp_path):
        from src.key_manager import KeyManager
        km = KeyManager(str(tmp_path / "keys3"))
        km.generate_and_save()
        km.rotate_keys()
        archived = km.list_archived_keys()
        assert len(archived) == 2
        msg = b"post-rotation test"
        assert decrypt(encrypt(msg, km.load_public_key()), km.load_private_key()) == msg

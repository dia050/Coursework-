import unittest
import os
from securecrypt_pki_gui_master import generate_rsa_keypair, rsa_encrypt_key, rsa_decrypt_key

class TestRSAEncryptKey(unittest.TestCase):
    def setUp(self):
        generate_rsa_keypair()

    def test_encrypt_decrypt_key(self):
        key = os.urandom(32)
        enc = rsa_encrypt_key(key)
        dec = rsa_decrypt_key(enc)
        self.assertEqual(key, dec)

if __name__ == "__main__":
    unittest.main()

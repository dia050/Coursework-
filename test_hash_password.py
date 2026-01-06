import unittest
from securecrypt_pki_gui_master import hash_password
import os

class TestHashPassword(unittest.TestCase):
    def test_hash_produces_bytes(self):
        salt = os.urandom(16)
        result = hash_password("mypassword", salt)
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 32)

if __name__ == "__main__":
    unittest.main()

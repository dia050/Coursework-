import unittest
from securecrypt_pki_gui_master import derive_aes_key
import os

class TestDeriveAESKey(unittest.TestCase):
    def test_key_length(self):
        salt = os.urandom(16)
        key = derive_aes_key("mypassword", salt)
        self.assertEqual(len(key), 32)

if __name__ == "__main__":
    unittest.main()

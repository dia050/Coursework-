import unittest
from unittest.mock import patch
from securecrypt_pki_gui_master import verify_master_password, MASTER_PASS_FILE, hash_password
import json, os

class TestVerifyMasterPassword(unittest.TestCase):
    def setUp(self):
        MASTER_PASS_FILE.unlink(missing_ok=True)
        salt = os.urandom(16)
        hashed = hash_password("pass123", salt)
        MASTER_PASS_FILE.write_bytes(json.dumps({"salt": salt.hex(), "hash": hashed.hex()}).encode())

    @patch('securecrypt_pki_gui_master.simpledialog.askstring', return_value="pass123")
    def test_verify_correct_password(self, mock_input):
        self.assertTrue(verify_master_password())

if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import patch
from securecrypt_pki_gui_master import set_master_password, MASTER_PASS_FILE

class TestSetMasterPassword(unittest.TestCase):
    @patch('securecrypt_pki_gui_master.simpledialog.askstring', side_effect=["pass123", "pass123"])
    def test_set_master_password(self, mock_input):
        MASTER_PASS_FILE.unlink(missing_ok=True)
        result = set_master_password()
        self.assertTrue(result)
        self.assertTrue(MASTER_PASS_FILE.exists())

if __name__ == "__main__":
    unittest.main()
#hello

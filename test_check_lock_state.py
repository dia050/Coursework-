import unittest
from securecrypt_pki_gui_master import check_lock_state, LOCK_STATE_FILE

class TestCheckLockState(unittest.TestCase):
    def setUp(self):
        LOCK_STATE_FILE.unlink(missing_ok=True)

    def test_not_locked(self):
        self.assertTrue(check_lock_state())

    def test_locked(self):
        LOCK_STATE_FILE.write_text("LOCKED")
        self.assertFalse(check_lock_state())

if __name__ == "__main__":
    unittest.main()

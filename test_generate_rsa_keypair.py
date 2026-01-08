import unittest
from pathlib import Path
from securecrypt_pki_gui_master import generate_rsa_keypair, PRIV_KEY, PUB_KEY

class TestGenerateRSAKeypair(unittest.TestCase):
    def setUp(self):
        for f in [PRIV_KEY, PUB_KEY]:
            f.unlink(missing_ok=True)

    def test_keypair_creation(self):
        generate_rsa_keypair()
        self.assertTrue(PRIV_KEY.exists())
        self.assertTrue(PUB_KEY.exists())

if __name__ == "__main__":
    unittest.main()

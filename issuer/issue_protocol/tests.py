from django.test import TestCase
from issue_protocol.crypto_modules import Signature
# Create your tests here.

class SignatureTestCase(TestCase):
	"""check Signature class"""
    def setUp(self):
        self.signature = Signature()

    def test_sign_performed_correctly(self):
    	obj = self.signature
    	sig, hash_f = obj.sign_message(obj.G, obj.sig_key,"TEST message")
    	res = obj.verify_signature(obj.G, obj.pub_key, sig, hash_f)
    	self.assertEqual(res, True)





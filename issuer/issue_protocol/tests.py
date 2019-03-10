from django.test import TestCase
from issue_protocol.crypto_modules import Signature
from petlib.ec import EcGroup
from petlib.ec import EcPt
from petlib.bn import Bn
from binascii import hexlify, unhexlify
# Create your tests here.

class SignatureTestCase(TestCase):
	"""check Signature class"""
	def setUp(self):
		self.signature = Signature()

	def test_sign_performed_correctly(self):
		obj = self.signature
		sig, hash_f = obj.sign_message(obj.G, obj.sig_key,"TEST message")
		res = obj.verify_signature(obj.G, obj.pub_key, sig, obj.hash_str("TEST message"))
		self.assertEqual(res, True)
		print("Test\n")
		# should be of type str
		#print(type(obj.hash_str("TEST message")))

	def test_other_g(self):
		"""
			Test if verify works if G2 is not the group from
			which pub_key was created.
			Tests show it works
		"""
		obj = self.signature
		sig, hash_f = obj.sign_message(obj.G, obj.sig_key,"TEST message")
		ob2 = Signature()
		G2 = ob2.G
		res = obj.verify_signature(G2, obj.pub_key, sig, ob2.hash_str("TEST message"))
		self.assertEqual(res, True)
		p1 = obj.pub_key.export()
		#print(type(p1))
		p2 = EcPt.from_binary(p1, G2)
		self.assertEqual(obj.pub_key, p2)
		
		# test encoding pk
		# get str
		str_p1 = hexlify(p1).decode()
		print(p1)
		print(unhexlify(str_p1.encode()))
		self.assertEqual(unhexlify(str_p1.encode()), p1)

		# test encoding hash
		h = ob2.hash_str("TEST message");
		str_ =  hexlify(h).decode()
		print("hash n")
		print(type(str_))

		# test .hex()
		self.assertEqual(Bn.from_hex(sig[0].hex()), sig[0])







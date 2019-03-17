from django.test import TestCase
from issue_protocol.crypto_modules import Signature, Blind_Sig, BlindSig
from petlib.ec import EcGroup
from petlib.ec import EcPt
from petlib.bn import Bn
from binascii import hexlify, unhexlify

from math import *
from random import SystemRandom
from Crypto.Hash import SHA256

from hashlib import sha256
# Create your tests here.
class SignatureTestCase(TestCase):
	"""check Signature class"""
	def setUp(self):
		self.signature = Signature()
	'''
	def Dtest_sign_performed_correctly(self):
		obj = self.signature
		sig, hash_f = obj.sign_message(obj.G, obj.sig_key,"TEST message")
		res = obj.verify_signature(obj.G, obj.pub_key, sig, obj.hash_str("TEST message"))
		self.assertEqual(res, True)
		print("Test\n")
		# should be of type str
		print(type(obj.sig_key))
		print(type(obj.pub_key))

		#print(type(obj.hash_str("TEST message")))

	def Dtest_other_g(self):
		"""
			Test if verify works if G2 is not the group from
			which pub_key was created.
			Tests show it works
		"""
		obj = self.signature
		sig, hash_f = obj.sign_message(obj.G, obj.sig_key,"TEST message")
		ob2 = Signature()
		G2 = ob2.G

		str_p1 = obj.pub_key.export().hex()
		p = EcPt.from_binary(unhexlify(str_p1), G2)
		
		res = obj.verify_signature(G2, p, sig, ob2.hash_str("TEST message"))
		self.assertEqual(res, True)
		p1 = obj.pub_key.export()
		#print(type(p1))
		p2 = EcPt.from_binary(p1, G2)
		self.assertEqual(obj.pub_key, p2)
		
		# test encoding pk
		# get str
		str_p1 = p1.hex()
		print(p1)
		print(unhexlify(str_p1))
		self.assertEqual(unhexlify(str_p1), p1)
		self.assertEqual(EcPt.from_binary(unhexlify(str_p1),obj.G),obj.pub_key)
		# test encoding hash
		h = ob2.hash_str("TEST message");
		str_ =  hexlify(h).decode()
		print("hash n")
		print(type(str_))
		# test .hex()
		self.assertEqual(Bn.from_hex(sig[0].hex()), sig[0])

	def test_blind_sig(self):
		obj = Blind_Sig()

		n,e = obj.pk

		# r must coprime with n
		r = n.random()
		one = Bn(1)
		# comoute coprime
		while gcd(n,r) != 1:
			r = r + one

		m = Bn(2) + Bn(128).random()

		m_b = obj.blind(r, m, obj.pk)
		s_b = obj.sign(m_b, obj.sk)
		print("TEST")
		print(Bn.get_prime(2).int())
		print(m)
		print(m_b)
		s = obj.unblind(r,s_b, obj.pk)
		self.assertEqual(m, obj.verify(s, obj.pk))
		self.assertNotEqual(m, m_b)
	'''
	def test_crypto(self):
		# AP key for signing.
		# User must know the pk and use it for blinding
		s1 = BlindSig()

		r = SystemRandom().randrange(s1.pk.n >> 10, s1.pk.n)

		m_unhas = Bn.get_prime(256).hex()
		# hashed
		#has = SHA256.new()
		#has.update(m_unhas)
		# m = has.digest()
		m = sha256(m_unhas.encode()).digest()

		msg_b = s1.blind(s1.pk, r, m)

		msg_b_s = s1.blind_sign(s1.sk, msg_b)

		msg_s = s1.unblind(msg_b_s, s1.pk,r)
		#h = SHA256.new()
		#h.update(msg_s)
		# m = h.digest()
		h = sha256(m_unhas.encode()).digest()
		self.assertEqual(True, s1.verify(s1.pk, h, msg_s))











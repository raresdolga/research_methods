"""
	Basic implmentation of cryptographic functions
"""
from petlib.bn import Bn
from hashlib import sha1
from petlib.ec import EcGroup
from petlib.ecdsa import *
from hashlib import sha256

from math import *

class Signature:
	""" Keys and functions to sign and verify a signaure
		Attributes:
			G (EcGroup): group used in eliptic curve sign algorithm
			sig_key (BN): private key used to sign a message
			pub_key (BN): public key used to verify a signature. Verifier must know it
	"""
	def __init__(self, G=None, s_k=None, p_k=None):
		if G is None:
			(self.G, self.sig_key, self.pub_key) = self.__setup()
		else:
			self.G = G
			self.sig_key = s_k
			self.pub_key = p_k


	# generate keys and group for signature
	def __setup(self):
		G = EcGroup()
		sig_key = G.order().random()
		pub_key = sig_key * G.generator()
		return (G, sig_key, pub_key)
	

	def sign_message(self,G, s_k, messg="Credential"):
		"""Performs an eliptic curve digital signiture
		   Args:
		   		G (EcGroup): group in which math is done. 
		   		s_k (Bn): secret key used to sign.
		   		messg (str): string to sign. Default is "Credential"
		   	Returns: (sig, hash) ((Bn, Bn),hash): signature, hash of messg
		"""
		# Hash the (potentially long) message into a short digest.
		digest = sha256(messg.encode()).digest()
		#sign hashed message
		signature = do_ecdsa_sign(G, s_k, digest)
		return (signature, digest)

	def verify_signature(self, G, p_k, sig, _hash):
		""" Verifies the signature provided aginst a public key
			The public key, group G must correspond to secret key used for signing
			Not the public key of the class
			Args:
				G (EcGroup):the group in which math is done.
				p_k (Bn): public key used to sign.
		   		sig (str): signature to ckeck
		   		_hash (str): hash of the initial messg
		   	Returns:
		   		verified (Bool): True if sig valid, False otherwise
		"""
		return do_ecdsa_verify(G, p_k, sig, _hash)

	def hash_str(self,messg):
		""" Signs the message
			Args:
				messg (str): the message to be hashed
			Return:
				hash_ (str): the hashed value of the messg
		"""
		return sha256(messg.encode()).digest()


""" Class that uses RSA blind signature
	Very slow for big numbers. Try Eliptic curve
"""
class Blind_Sig:
	def __init__(self):
		self.pk, self.sk = self._setup()
		# example of hot to generate r,
		# must be genetrated by user and 2 < r < n
		n,e = self.pk
		self.r = Bn.from_decimal("2") + n.random()


	def _setup(self):
		one = Bn.from_decimal("1")
		p = Bn(13)#Bn.get_prime(2)
		q = (17)#Bn.get_prime(2)
		n = p * q
		phi = (p - one) * (q - one)
		
		e =  one + (phi).random()

		while gcd(phi,e) != 1:
			e = e + one

		d = e.mod_inverse(m=phi)
	
		pub = (n,e)
		priv = (n,d)
		return pub, priv

	# assumes m is a big number
	# r must be computed by the user
	# pk is the public key of the signer
	def blind(self,r, m, pk):
		n,e = pk
		m_b = m.mod_mul(r**e,n)
		return m_b

	def sign(self,m_b, sk):
		n,d = sk
		return m_b.mod_pow(d,n)

	def unblind(self,m_s_b, pk,r):
		n,e = pk
		# r can 
		m_s = m_s_b.mod_mul((r.mod_inverse(m=n)), n)
		return m_s

	# verifies an unblinded signed message
	def verify(self,m_s, pk):
		n,e = pk
		return m_s.mod_pow(e, n)

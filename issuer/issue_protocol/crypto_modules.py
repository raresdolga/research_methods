"""
	Basic implementation of cryptographic functions
"""
from petlib.bn import Bn
from hashlib import sha1
from petlib.ec import EcGroup
from petlib.ecdsa import *
from hashlib import sha256

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

	def verify_signature(self, G, p_k, sig, messg):
		""" Verifies the signature provided aginst a public key
			The public key, group G must correspond to secret key used for signing
			Not the public key of the class
			Args:
				G (EcGroup):the group in which math is done.
				p_k (Bn): public key used to sign.
		   		sig (str): signature to ckeck
		   		messg (str): the initial messg
		   	Returns:
		   		verified (Boolean): True if sig valid, False otherwise
		"""
		hash_ = self.hash_str(messg)
		return do_ecdsa_verify(G, p_k, sig, hash_)

	def hash_str(self,messg):
		""" Signs the message
			Args:
				messg (str): the message to be hashed
			Return:
				hash_ (str): the hashed value of the messg
		"""
		return sha256(messg.encode()).digest()



		
		

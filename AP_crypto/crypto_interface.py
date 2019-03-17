from crypto_modules import Signature, Blind_Sig
from petlib.bn import Bn
from petlib.ec import EcPt
import sys
from binascii import hexlify, unhexlify

""" Script to call functions in cryptografic modules.
	Verifies signatures and signs using arguments passed 
	from command line.
"""
sign = Signature()
blind_Sig = Blind_Sig()

def _str_to_bytes(mesg_dec):
	# Convert pk_enc from string to hex
	_hex = mesg_dec.encode()
	# Convert from hex to binary
	_binary = unhexlify(_hex)
	return _binary

def _bytes_to_str(enc):
	return hexlify(enc).decode()

def verify_sig(pk_str, sig_hex, hash_str):
	""" Verifies if the signature is valid
		Args:
			pk_str (str): The public key encoded. Must be decode in bytes, than in EcPt object
			sig_hex (lits(str)): the signaure. A list with 2 hex-strings
			hash_str (str): The has of credNo, cred. Data which was signed by issuer
		Returns:
			res (Bool): true if the signature is valid, False otherwise
	"""
	
	pk_binary = _str_to_bytes(pk_str)
	# decode public key as EcPt object
	pk = EcPt.from_binary(pk_binary, sign.G)
	# get the hashed message as bytes class
	_hash = _str_to_bytes(hash_str)

	# decode sig in (Bn, Bn) type
	sig = (Bn.from_hex(sig_hex[0]), Bn.from_hex(sig_hex[1]))

	#p_k is not the public key of G, but of the signer
	# verify works even if signer used different group object,
	# but the same keys
	# G has other sets of keys, use them to sign as AP
	return sign.verify_signature(sign.G, pk, sig, _hash)


def blind_sign(m_b_enc, sk_signer):
	# desirialize m_b as it is received as a Bn
	m_b = Bn.from_hex(m_b_enc)

	# sk_signer is a Bn in case of RSA
	sk = Bn.from_hex(sk_signer)
	return blind_Sig.sign(m_b, sk)

def main():
	func = sys.argv[1] # 0 is the name of script
	if func == "verify":
		#public key
		pk_str = sys.argv[2]
		# signature
		sig_hex = sys.argv[3]
		# hash of user key associated with the policy
		# can get just the original key and hash it here
		hash_ = sys.argv[4]
		print(verify_sig(pk_str, sig_hex, hash_))
	if func == "blind_sign":
		# RP blinded number
		rp_blind = sys.argv[2]
		# public key of the signer
		pk_sg = sys.argv[3]
		print(blind_sign(rp_blind, pk_sg))
	# return a bn serialized as a string to send to the user
	if func == "get_AP_message":
		bn = Bn.get_prime(128)
		print(bn.hex())
	if func == "gen_sign_keys":
		# This are keys used by RSA to blindly sign 
		# different from normal signature keys
		# Have other types as well
		# tuple of 2 Bn
		# n = firts, e = second
		pub = blind_Sig.pk
		# n = first, d = second
		priv = blind_Sig.sk
		print("Public key:")
		print([pub[0].hex(), pub[1].hex()])
		print("Private key:")
		print([priv[0].hex(), priv[1].hex()])


if __name__ == "__main__":
	main()
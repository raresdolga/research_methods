from crypto_modules import Signature
from petlib.bn import Bn
from petlib.ec import EcPt
import sys
from binascii import hexlify, unhexlify

""" Script to call functions in cryptografic modules.
	Verifies signatures and signs using arguments passed 
	from command line.
"""
G = Signature()

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
	
	pk_binary = _str_to_bytes(pk_enc)
	# decode public key as EcPt object
	pk = EcPt.from_binary(pk_binary, G)
	# get the hashed message as bytes class
	_hash = _str_to_bytes(hash_str)

	# decode sig in (Bn, Bn) type
	sig = (Bn.from_hex(sig_hex[0]), Bn.from_hex(sig_hex[1]))

	#p_k is not the public key of G, but of the signer
	# verify works even if signer used different group object,
	# but the same keys
	# G has other sets of keys, use them to sign as AP
	return verify_signature(G, pk, sig, _hash)


def blind_sign():
	pass


def main():
	func = sys.argv[1] # 0 is the name of script
	if func == "verify":
		pk_str = sys.argv[2]
		sig_hex = sys.argv[3]
		hash_ = sys.argv[4]





if __name__ == "__main__":
	main()
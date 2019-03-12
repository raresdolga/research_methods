"""
	Basic implementation of cryptographic functions
"""
import msgpack
from petlib.bn import Bn
from petlib.ec import EcGroup
from petlib.ecdsa import *
from hashlib import sha256
from binascii import hexlify


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


    def sign_message(self, messg, G = None, s_k = None):
        """
            Performs an elliptic curve digital signiture
            Args:
                   G (EcGroup): group in which math is done.
                   s_k (Bn): secret key used to sign.
                   messg (str): string to sign. Default is "Credential"
            Returns: (sig, hash) ((Bn, Bn),hash): signature, hash of messg
        """
        # Set defaults if no parameters are passed
        if G is None: G = self.G
        if s_k is None: s_k = self.sig_key

        # Hash the (potentially long) message into a short digest.
        digest = self.hash_str(messg).encode()

        # sign hashed message
        signature = do_ecdsa_sign(G, s_k, digest)
        return signature, digest.decode()

    def verify_signature(self, G, p_k, sig, messg):
        """
            Verifies the signature provided aginst a public key
                The public key, group G must correspond to secret key used for signing
                Not the public key of the class
            Args:
                G (EcGroup):the group in which math is done.
                p_k (Bn): public key used to sign.
                sig (str): signature to check
                messg (str): the initial message
            Returns:
                verified (Boolean): True if sig valid, False otherwise
        """
        # hash_ = self.hash_str(messg)
        return do_ecdsa_verify(G, p_k, sig, messg)

    def hash_str(self, messg):
        """ Signs the message
            Args:
                messg (str): the message to be hashed
            Return:
                hash_ (str): the hashed value of the messg
        """
        return sha256(messg.encode()).hexdigest()


class CredentialVerifier():
    group = EcGroup()

    @classmethod
    def verify_signature(self, ver_key, sig, data, g=None):
        """ Verifies the signature provided against a public key
            The public key, group G must correspond to secret key used for signing
            Not the public key of the class
            Args:
                group (EcGroup):the group in which math is done.
                ver_key (Bn): public key used to sign.
                   sig (str): signature to check
                   messg (str): the initial message
               Returns:
                   verified (Boolean): True if sig valid, False otherwise
        """
        hash_ = self.hash_str(data)
        if self.group == None:
            return do_ecdsa_verify(self.group, ver_key, sig, hash_)
        else:
            return do_ecdsa_verify(g, ver_key, sig, hash_)

    @classmethod
    def hash_str(self, messg):
        """ Signs the message
            Args:
                messg (str): the message to be hashed
            Return:
                hash_ (str): the hashed value of the messg
        """
        return sha256(messg.encode()).hexdigest()


class Custom_Encode_Decode:
    def __eq__(self, other):
       return isinstance(other, Custom_Encode_Decode)

    def enc_CustomClass(obj):
        if isinstance(obj, Custom_Encode_Decode):
            return msgpack.ExtType(10, b'')
        raise TypeError("Unknown type: %r" % (obj,))

    def dec_CustomClass(code, data):
        if code == 10:
            return Custom_Encode_Decode()
        return msgpack.ExtType(code, data)
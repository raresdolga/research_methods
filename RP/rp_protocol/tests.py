import json
from binascii import hexlify

from django.test import TestCase
from petlib import pack
from rest_framework.renderers import JSONRenderer
from rest_framework.test import RequestsClient, APIRequestFactory

# Create your tests here.
from rp_protocol.crypto import Signature
from rp_protocol.helpers import verify_policy
from rp_protocol.models import DummyCredential, UserSessionID
from rp_protocol.policies import PresentationPolicy
from rp_protocol.serializers import CredentialSerializer, PolicySerializer


class CredentialTests(TestCase):
    def setUp(self):
        self.cred = CredentialSerializer(DummyCredential(age=21, nationality="Dutch"))
        self.sig = Signature()

    def test_cred_to_string(self):
        data = self.cred.data.__str__()
        self.assertEqual(data, "{'age': 21, 'nationality': 'Dutch'}")

    def test_cred_hash(self):
        data = self.cred.data.__str__()
        cred_sig, cred_dig = self.sig.sign_message(data)
        digest = self.sig.hash_str(data)
        self.assertEqual(cred_dig, digest)

    def test_create_dummy_policy(self):
        # Create dummy objects
        sessionID = UserSessionID("44848f0642c411e9b210d663bd873d93").sessionID
        cred = CredentialSerializer(DummyCredential(age=21, nationality="Dutch"))
        false_cred = CredentialSerializer(DummyCredential(age=22, nationality="English"))

        # Create True signatures and digests
        sessionID_sig, sessionID_digest = self.sig.sign_message(sessionID)
        cred_sig, cred_digest = self.sig.sign_message(cred.get_string())

        # Create False signatures and digests
        cred_sig_false, cred_digest_false = self.sig.sign_message(false_cred.get_string())

        # Verify signatures
        sessionID_verify = self.sig.verify_signature(self.sig.G, self.sig.pub_key, sessionID_sig, sessionID_digest)
        cred_verify = self.sig.verify_signature(self.sig.G, self.sig.pub_key, cred_sig, cred_digest)
        cred_digest_verify = cred.get_hash() == cred_digest

        # Should be false
        false_cred_verify = self.sig.verify_signature(self.sig.G, self.sig.pub_key, cred_sig_false, cred_digest)
        false_digest_verify = self.sig.verify_signature(self.sig.G, self.sig.pub_key, cred_sig, cred_digest_false)
        hash_not_same = false_cred.get_hash() == cred.get_hash()

        # Checks True
        self.assertTrue(sessionID_verify)
        self.assertTrue(cred_verify)
        self.assertTrue(cred_digest_verify)

        # Checks False
        self.assertFalse(false_cred_verify)
        self.assertFalse(false_digest_verify)
        self.assertFalse(hash_not_same)

class APITests(TestCase):
    def test_live(self):
        client = RequestsClient()
        response = client.get('http://127.0.0.1:8000')
        assert response.status_code == 200

class HelperTests(TestCase):
    def setUp(self):
        self.cred = CredentialSerializer(DummyCredential(age=21, nationality="Dutch"))
        self.sig = Signature()

    def test_verify_policy(self):
        # Create dummy objects
        sessionID = UserSessionID("44848f0642c411e9b210d663bd873d93").sessionID
        cred = CredentialSerializer(DummyCredential(age=21, nationality="Dutch"))
        policy = PresentationPolicy("44848f0642c411e9b210d663bd873d93")
        policy.ap_key = hexlify(self.sig.pub_key.export()).decode("utf8")
        policy.credential = DummyCredential(age=21, nationality="Dutch")

        # Create True signatures and digests
        policy.sessionID_sig, policy.sessionID_hash = self.sig.sign_message(sessionID)
        policy.cred_sig, policy.cred_hash = self.sig.sign_message(cred.get_string())
        print(JSONRenderer().render(PolicySerializer(policy).data))
        res = verify_policy(PolicySerializer(policy).data)
        self.assertTrue(res)
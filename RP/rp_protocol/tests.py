import io
import re
from binascii import unhexlify
from uuid import uuid4

from django.test import TestCase
from petlib.bn import Bn
from petlib.ec import EcPt
from rest_framework.parsers import JSONParser
from rest_framework.test import RequestsClient

# Create your tests here.
from rp_protocol.crypto import Signature
from rp_protocol.helpers import get_sig_from_string
from rp_protocol.models import UserPolicyInformation
from rp_protocol.serializers import PolicySerializer, APKeySerializer


class APITests(TestCase):
    def setUp(self):
        self.sig = Signature()
        self.client = RequestsClient()
        self.url = 'http://127.0.0.1:8000'

    def test_live(self):
        response = self.client.get(self.url)
        assert response.status_code == 200

    def test_request_access(self):
        response = self.client.get(self.url+'/request_access')

        regex = re.compile('{"sessionID": "[0-9a-fA-F]*", "sessionID_sig": null, "accepted_policies": "[0-9a-fA-F]*"}')
        match = re.fullmatch(regex, response.content.decode("utf-8"))

        assert match.string is not None

    def test_verify_policy(self):
        # Create new policy
        policy = UserPolicyInformation(sessionID="71a7de77413e42ab814e53c32acbc079", accepted_policies=self.sig.pub_key)
        policy.sessionID_sig = self.sig.sign_message(policy.sessionID)

        assert policy.accepted_policies == self.sig.pub_key

        # Serialize the policy
        serialized = PolicySerializer(policy).data

        # Post the policy
        response = self.client.post(self.url + '/verify_test', serialized)
        content = response.content

        # Decode the received policy
        data = JSONParser().parse(io.BytesIO(content))
        restored = PolicySerializer(data=data)

        # Make sure correctly decoded
        assert restored.is_valid()

        public_key = EcPt.from_binary(unhexlify((data.get("accepted_policies")).encode()), self.sig.G)
        sig = get_sig_from_string(data.get("sessionID_sig"))

        # Check signature against public key
        assert Signature().verify_signature(public_key, sig, policy.sessionID)

class SerializationTests(TestCase):
    @classmethod
    def setUp(self):
        self.sig = Signature()

    # Test checks that the serialized key is in the form that is expected
    def test_pub_key_serialization(self):
        regex = re.compile("{'ap_key': '[0-9a-fA-F]*'}")
        pub_key = self.sig.pub_key
        data = str(APKeySerializer(pub_key).data)
        match = re.fullmatch(regex, data)
        assert match.string is not None

    # Checks that the response of access_request is populated with sessionID and policy
    def test_new_session_ID(self):
        userSession = UserPolicyInformation(uuid4().hex)
        data = str(PolicySerializer(userSession).data)

        regex = re.compile("{'sessionID': '[0-9a-fA-F]*', 'sessionID_sig': None, 'accepted_policies': '[0-9a-fA-F]*'}")
        match = re.fullmatch(regex, data)

        assert match.string is not None

    def test_create_from_serializer(self):
        new = PolicySerializer(uuid4().hex)
        print(new.data)

    def test_uuid_to_hex(self):
        uuid = uuid4().hex
        bn = Bn.from_hex(uuid)
        print(bn)

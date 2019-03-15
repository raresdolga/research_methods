import io
from binascii import unhexlify

from petlib.bn import Bn
from petlib.ec import EcPt, EcGroup
from rest_framework import serializers
from rest_framework.parsers import JSONParser

from rp_protocol.models import UserPolicyInformation
from rp_protocol.serializers import PolicySerializer
from rp_protocol.crypto import Signature


def get_sig_from_string(sig):
    sig = sig[1:-1]
    r, s = sig.split(", ")
    r = Bn.from_decimal(r)
    s = Bn.from_decimal(s)
    return r, s

def check_policy_format(policy):
    # stream = io.BytesIO(policy)
    # data = JSONParser().parse(policy)
    serializer = PolicySerializer(data=policy)
    if serializer.is_valid(raise_exception=True):
        return serializer
    else:
        raise serializers.ValidationError("Presented Policy is malformed")


def verify_policy(policy):
    try:
        policy = check_policy_format(policy)
        data = policy.data

        # Check if sessionID exists in DB
        if UserPolicyInformation.objects.filter(pk=data.get('sessionID')).exists():
            sessionEntry = UserPolicyInformation.objects.get(pk=data.get('sessionID'))

            # Check that the public keys match
            assert data.get('accepted_policies') == sessionEntry.accepted_policies

            public_key = EcPt.from_binary(unhexlify(sessionEntry.accepted_policies.encode()), EcGroup(713))
            sig = get_sig_from_string(data.get("sessionID_sig"))

            # Make sure the SessionID is verified
            assert Signature.verify_signature(public_key, sig, data.get("sessionID"))

            # Add to the DB
            sessionEntry.verified = True
            sessionEntry.sessionID_sig = data.get('sessionID_sig')
            sessionEntry.save()
            return True
        else:
            return False
    except:
        return False

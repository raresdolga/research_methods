from binascii import unhexlify

from petlib.bn import Bn
from petlib.ec import EcPt, EcGroup
from rest_framework import serializers

from rp_protocol.crypto import Signature
from rp_protocol.models import UserPolicyInformation
from rp_protocol.serializers import PolicySerializer


def get_sig_from_string(sig):
    sig = sig[1:-1]
    r, s = sig.split(", ")
    r = Bn.from_decimal(r)
    s = Bn.from_decimal(s)
    return r, s

def check_policy_format(policy):
    """
        Checks that the format of the policy is correct and that all the
            required fields are supplied
        Args:
           policy (dict): json dict received from the user.
        Returns:
           serializer (serializer): serializer if True, raise exception otherwise.
    """

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
            if not data.get('accepted_policies') == sessionEntry.accepted_policies: return False

            public_key = EcPt.from_binary(unhexlify(sessionEntry.accepted_policies.encode()), EcGroup(713))
            sig = get_sig_from_string(data.get("sessionID_sig"))

            # Make sure the SessionID is verified
            if not Signature.verify_signature(public_key, sig, data.get("sessionID")): return False

            # Add to the DB
            sessionEntry.verified = True
            sessionEntry.sessionID_sig = data.get('sessionID_sig')
            sessionEntry.save()
            return True
        else:
            return False
    except:
        return False

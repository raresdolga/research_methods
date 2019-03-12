import io
from rest_framework import serializers
from rest_framework.parsers import JSONParser
from rp_protocol.serializers import PolicySerializer
from rp_protocol.crypto import CredentialVerifier


def check_policy_format(policy):
    stream = io.BytesIO(policy)
    data = JSONParser().parse(stream)
    serializer = PolicySerializer(data=data)
    if serializer.is_valid(raise_exception=True):
        return serializer
    else:
        raise serializers.ValidationError("Presented Policy is malformed")


def verify_policy(policy):
    try:
        policy = check_policy_format(policy)

        sessionID_valid = CredentialVerifier.verify_signature(policy.ap_key, policy.sessionID_sig, policy.sessionID_hash)
        cred_valid = CredentialVerifier.verify_signature(policy.ap_key, policy.cred_sig, policy.cred_hash)
        hash_valid = CredentialVerifier.hash_str(policy.credential.data) == policy.cred_hash

        # Policy is only fulfilled if all three are fulfilled
        if sessionID_valid and cred_valid and hash_valid:
            return True
        else:
            return False
    except:
        return False


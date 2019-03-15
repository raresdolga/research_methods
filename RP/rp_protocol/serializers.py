from petlib import pack
from rest_framework import serializers

from rp_protocol.models import UserPolicyInformation


class SignatureSerializer(serializers.Serializer):
    r = serializers.SerializerMethodField()
    s = serializers.SerializerMethodField()

    def get_r(self, obj):
        return obj[0].hex()

    def get_s(self, obj):
        return obj[1].hex()

class APKeySerializer(serializers.Serializer):
    ap_key = serializers.SerializerMethodField()

    def get_ap_key(self, obj):
        str = pack.encode(obj)
        return str


class PolicySerializer(serializers.Serializer):
    sessionID = serializers.CharField()
    sessionID_sig = serializers.CharField()
    accepted_policies = serializers.CharField()

    class Meta:
        model = UserPolicyInformation()
        fields = ('sessionID', 'sessionID_sig','accepted_policies')
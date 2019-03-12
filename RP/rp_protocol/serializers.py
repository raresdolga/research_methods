from petlib import pack
from rest_framework import serializers
from rest_framework.fields import SerializerMethodField
import binascii
from rp_protocol.crypto import Signature
from rp_protocol.models import DummyCredential


class UserSerializer(serializers.Serializer):
    sessionID = serializers.UUIDField(format='hex')

class CredentialSerializer(serializers.Serializer):
    age = serializers.IntegerField()
    nationality = serializers.CharField(max_length=100)

    def get_hash(self):
        str = self.data.__str__()
        return Signature().hash_str(str)

    def get_string(self):
        return self.data.__str__()

    class Meta:
        model = DummyCredential
        fields = ('age', 'nationality')

class SignatureSerializer(serializers.Serializer):
    sig = serializers.SerializerMethodField()

    def get_sig(self, obj):
        return pack.encode(obj)


class HashSerializer(serializers.Serializer):
    hash = serializers.SerializerMethodField()

    def get_hash(self, obj):
        return obj


class PolicySerializer(serializers.Serializer):
    sessionID_hash = HashSerializer()
    sessionID_sig = SignatureSerializer()
    cred_hash = HashSerializer()
    cred_sig = SignatureSerializer()
    ap_key = serializers.CharField()
    credential = CredentialSerializer()

    class Meta:
        fields = ('sessionID_hash', 'sessionID_sig', 'cred_hash', 'cred_sig', 'ap_key', 'credential')

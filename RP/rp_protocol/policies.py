from rp_protocol.crypto import Signature
from rp_protocol.models import DummyCredential
from rp_protocol.serializers import PolicySerializer

class PresentationPolicy():
    def __init__(self, sessionID):
        # Privacy Requirements
        self.sessionID_hash = Signature().hash_str(sessionID)
        self.sessionID_sig = None
        self.cred_hash = None
        self.cred_sig = None
        self.ap_key = None

        # Credential Requirements
        self.credential = DummyCredential(age=None, nationality=None)

    def get_policy(self):
        return PolicySerializer(self).data

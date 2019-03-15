from django.db import models

class UserPolicyInformation(models.Model):
    sessionID = models.CharField(primary_key=True, unique=True, editable=False, max_length=256)
    sessionID_sig = models.CharField(max_length=512, default=None, null=True)
    accepted_policies = models.CharField(max_length=256, default="0355fb5dfc02bca617688ec3c02c4e41bf7705a32a0fd5f87af6baf100")
    verified = models.BooleanField(default=False)


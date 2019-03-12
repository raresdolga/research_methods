from django.db import models


class UserSessionID(models.Model):
    sessionID = models.UUIDField(primary_key=True, unique=True, editable=False)



class DummyCredential(models.Model):
    age = models.IntegerField(editable=False)
    nationality = models.CharField(max_length=100, editable=False)

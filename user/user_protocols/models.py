from django.db import models

# Create your models here.
class PublicPrivateKeys(models.Model):
    public_keys = models.TextField(blank = True)
    private_keys = models.TextField(blank = True)
    groups = models.TextField(blank = True)
    policy = models.CharField(max_length = 500, unique = True)

class Token(models.Model):
    token = models.TextField(blank = False)
    user = models.TextField(blank = False)

class Test(models.Model):
    revert = models.TextField(blank = True)

class newToken(models.Model):
    token = models.TextField(blank = False)
    user = models.TextField(blank = False)
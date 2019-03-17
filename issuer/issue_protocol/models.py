from django.db import models

# Create your models here.
class Credential_Batch(models.Model):
	batchId = models.CharField(max_length = 500)
	user_name = models.CharField(max_length = 120)
	# the list of public keys serialized as a json string
	public_keys = models.TextField(blank = True)

class Key(models.Model):
	keyId = models.AutoField(primary_key=True)
	publicKey = models.TextField()
	secretKey = models.TextField()

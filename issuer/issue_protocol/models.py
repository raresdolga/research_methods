from django.db import models

# Create your models here.
class Credential_Batch(models.Model):
	batchId = models.CharField(max_length = 500, unique=True)
	user_name = models.CharField(max_length = 120)
	# the list of public keys serialized as a json string
	public_keys = models.TextField(blank = True)

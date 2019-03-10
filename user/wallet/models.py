from django.db import models

class Credential(models.Model):
  date = models.DateTimeField('date created')
  issuer = models.CharField(max_length=200, default='No issuer')

  def get_date(self):
    return self.date

  def get_issuer(self):
    return self.issuer
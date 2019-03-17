from django.contrib import admin
from issue_protocol.models import Credential_Batch, Key

# Register your models here.
admin.site.register(Credential_Batch)
admin.site.register(Key)
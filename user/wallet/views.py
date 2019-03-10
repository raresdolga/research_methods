from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render

from .models import Credential
from .forms import NewCredentialForm

from datetime import datetime


def index(request):
  latest_credential_list = Credential.objects.order_by('-date')[:5]
  context = {
    'latest_credential_list': latest_credential_list,
  }
  return render(request, 'wallet/index.html', context)

def detail(request, credential_id):
  credential = get_object_or_404(Credential, pk=credential_id)
  return render(request, 'wallet/detail.html', {'credential': credential})

def add(request):
  print("It's valid!")
  return render(request, 'wallet/retrieve-credential.html')

def addCredentialForm(request):
  if request.method == 'POST':
    form = NewCredentialForm(request.POST)
    if form.is_valid():

      new_credential = Credential()
      new_credential.date = datetime.now()
      new_credential.issuer = NewCredentialForm.issuer

      new_credential.save()

  return render(request, 'wallet/detail.html', {'credential': new_credential})
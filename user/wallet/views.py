from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect

from .models import Credential
from .forms import Passport

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

def use_credential(request):
  return render(request, 'wallet/use_credential.html')

def select_policy(request):
  return render(request, 'wallet/select_policy.html')

def login_idp(request):
  print("It's valid!")
  return render(request, 'wallet/login_idp.html')

def contact(request):
  if request.method == 'POST': # If the form has been submitted...
    data = request.POST['first_name']
    print(type(data))

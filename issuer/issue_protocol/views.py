from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.http import HttpResponse
# Create your views here.

def signup(request):
	if request.method == 'POST':
		form = UserCreationForm(request.POST)
		if form.is_valid():
			user = form.save()
			username = form.cleaned_data.get('username')
			raw_password = form.cleaned_data.get('password1')
			# authenticate(username=username, password=raw_password)
			login(request, user)
			return redirect('accounts:get_credential')
	else:
		form = UserCreationForm()
	return render(request, 'registration/signup.html', {'form': form})


def login_view(request):
	"""Represents the issuance policy"""
	if request.method == 'POST':
		form = AuthenticationForm(data=request.POST)
		if form.is_valid():
			user = form.get_user()
			login(request, user)
			return redirect('accounts:get_credential')
	else:
		form = AuthenticationForm()
	return render(request, 'registration/login.html', {'form':form})

@api_view(['GET', 'POST'])
@permission_classes((IsAuthenticated,))
def get_credential(request):
	""" Creates a credential and sends it to the user
		Args:
			 request (request): a request object containing the key for 
				desired attribyutes
	"""
	logout(request)
	return HttpResponse("return this credential");

@api_view(['GET'])
@permission_classes((AllowAny,))
def request_credential(request):
	"""Asks this issuer for a credential
	   Redirects to login (issuance policy)
	"""
	return HttpResponse("These 2 servers communicated succesfully");

def _find_attribute_vals(attribute_keys):
	"""Queries the database to find values for attributes requested
		Args: 
			attribute_keys (list(str)): list of keys of attributes like name, age, etc
		Returns: credential (dict): key-value pairs - attributes in credential
	"""
	# dummy function for prototype
	cred_attr = {}
	dummy = 'value'
	cnt = 1
	for key in attribute_keys:
		cred_attr[key] = dummy + str(cnt)
		cnt += 1
	#print(cred_attr)
	return cred_attr

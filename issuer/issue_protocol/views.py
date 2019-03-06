from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.http import HttpResponse

# django rest
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny

#User Interface Views.

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

# API views - requries rest auth

@api_view(["POST"])
@permission_classes((AllowAny,))
def login_api(request):
    """ Implements login using tokens
        Given a username and password returns a valid token 
    """
    username = request.data.get("username")
    password = request.data.get("password")
    if username is None or password is None:
        return Response({'error': 'Please provide both username and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=username, password=password)
    if not user:
        return Response({'error': 'Invalid Credentials'},
                        status=HTTP_404_NOT_FOUND)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({'token': token.key}, status=HTTP_200_OK)



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

@api_view(['GET'])
@permission_classes((AllowAny,))
def test_connect(request):
	"""Test the HTTPS connection
	"""
	#response = redirect("accounts:login")
	
	return HttpResponse("These 2 servers communicated succesfully");

def _verify_attribute_vals(attributes):
	"""Queries the database to verify values for attributes requested
		Args: 
			attributes (dict): list of keys of attributes like name, age, etc
		Returns: (ok, invalid_fileds) (Boolean, list): flag represents if
		all attribute values are correct. list has keys of attributes with invalid value
	"""
	# dummy function for prototype
	cred_attr = {"name":"user1", "age":"30", "City":"London"}
	invalid_fields = []
	ok = True
	dummy = 'value'
	for key in attributes:
		if cred_attr[key] != attributes[key] :
			ok = False
			invalid_fields.append(key)
	return (ok, invalid_fields)

from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

# django rest
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)

from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token

import urllib.request
import json
import ssl
import logging

from issue_protocol.crypto_modules import Signature

logger = logging.getLogger(__name__)
#one signature setup - use just one set of keys
sign_algh = Signature()

# User Interface Views. - Not relevent for the API
"""The following functions are mostly for frontend authentication"""

@csrf_exempt
def signup(request):
	"""Example of how frontend implements signup.
		The html files are in templates/registration folder folder 
	"""
	if request.method == 'POST':
		form = UserCreationForm(request.POST)
		if form.is_valid():
			user = form.save()
			username = form.cleaned_data.get('username')
			raw_password = form.cleaned_data.get('password1')
			login(request, user)
			return redirect('accounts:get_credential')
	else:
		form = UserCreationForm()
	return render(request, 'registration/signup.html', {'form': form})


def login_view(request):
	"""Frontend login. Find html files in templates/registration"""
	if request.method == 'POST':
		form = AuthenticationForm(data=request.POST)
		if form.is_valid():
			user = form.get_user()
			login(request, user)
			return redirect('accounts:get_credential')
	else:
		form = AuthenticationForm()
	return render(request, 'registration/login.html', {'form':form})


#===============API views - requries rest auth=====================
"""Views that implement issuer API functionality """

@api_view(["POST"])
@permission_classes((AllowAny,))
def login_api(request):
    """ Implements login.
        Args: 
        	request (POST): Body has a username and password in JSON format
        Return:
     		tok, Status (JSON, int) Returns a valid token as a JSON objec
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



@api_view(['POST'])
@permission_classes((IsAuthenticated,))
def get_credential(request):
	""" Creates a credential and sends it to the user
		Args:
			 request (request): a request object containing the key for 
				desired attribyutes
	"""
	data = request.data
	logger.error(data)
	logger.warning("Hello")
	#verify attributes values
	(check, err_attr) = _verify_attribute_vals(data['attributes'])
	response = {}
	if not check :
		response['valid'] = False
		response['invalid attributes'] = err_attr
		response['credential'] = None
		return Response(response, status=HTTP_200_OK)
	# attributes given are correct
	response['valid'] = True
	response['invalid attributes'] = []
	# get credential as a dictionary
	response['credential'] = _create_cred(data)
	#logger.error("Test \n")
	#logger.error(json.dumps(response))
	# send blinded cred_id to be saved on the ledger for revocation
	return Response(response, status=HTTP_200_OK)

@api_view(['GET'])
@permission_classes((AllowAny,))
def request_credential(request):
	"""Asks this issuer for a credential
	   Redirects to login (issuance policy)

	"""
	return HttpResponse("These 2 servers communicated succesfully")


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
	for key in attributes:
		if not(key in cred_attr and cred_attr[key] == attributes[key]) :
			ok = False
			invalid_fields.append(key)
	return (ok, invalid_fields)

def _create_cred(data):
	""" Creates a credential using dictionaries
		Args: 
			data(dict): data sent by user to be verified and cred_nr
		Return:
			cred(dict): credential in the form of a dictionary. The
			signiture is a tuple of petlib.BN in code.
			Passed to json as an array of hex strings, for each elem in the tuple
	"""
	credential = {}
	#blindly set credential id - encrypted when sent
	credential['cred_id'] = data['cred_id']
	# put attributes
	credential['attributes'] = data['attributes']
	# compute sitring to sign
	list_str = [str(credential['attributes']), str(credential['cred_id'])]
	str_cred = "".join(list_str)
	# logg how the string looks
	logger.error('Encoding cred\n')
	logger.error(str_cred)
	# sign string of credential
	sig, hash_ = sign_algh.sign_message(sign_algh.G, sign_algh.sig_key, str_cred)
	# add signature - hex of petlib.BNs in the tuples
	# use from_hex() to transform back in petlib.BN
	logger.error(type(sig[0].hex()))
	credential['signaure'] = [sig[0].hex(), sig[1].hex()]
	return credential

#==================Functions used for testing connection=================

""" Functions used for mannual tests of connection between 2 servers
	Do not respect the design of our system, but do not delete them yet.
	Use the endpoints defined by this functions for quick testing
	Examples of how to handle or send requests. 
	Look in issue_protocol/urls.py to see how the paths of the views
"""
@api_view(['GET'])
@permission_classes((IsAuthenticated,))
def test_connect(request):
	""" Test the HTTPS connection.
		Handles a HTTPS request from a different server
		Send a response if succesfully passed the authentication
	"""
	return HttpResponse("These 2 servers communicated succesfully");

@api_view(['GET'])
@permission_classes((AllowAny,))
def test_ledger(request):
	""" Test connection with the ledger.
		Send a https request to the ledger.
		Mock data sent
	"""
	"""
	cert_path = "/etc/apache2/ssl/apache.crt";
	url = 'https://51.145.54.197:3000/api/Authenticator'
	
	data = {
	  "$class": "org.example.biznet.CredentialCard",
	  "credId": "string",
	  "cardDescription": "string",
	  "active": True
	}
	response =  urllib.request.urlopen(url, data= data, cafile=cert_path)
	content =  response.read().decode(response.headers.get_content_charset())
	return JsonResponse(data)
	"""
	# Dhen's code
	try:
		url = "http://aires-aps.uksouth.cloudapp.azure.com:3000/api/CredentialCard"
		data = { "$class" : "org.example.biznet.CredentialCard",
		 "credId" : "3", "cardDescription":"hello","active": True } # Data
		req = urllib.request.Request(url)
		req.add_header('Content-type', 'application/json; charset=utf-8')
		json_data = json.dumps(data)
		json_as_bytes = json_data.encode('utf-8')
		response = urllib.request.urlopen(req, json_as_bytes)
	except Exception as e:
		logger.error(e)
		return HttpResponse(e)
	return Response(response)

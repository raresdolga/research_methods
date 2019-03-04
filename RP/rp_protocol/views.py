from django.shortcuts import render
from django.http import JsonResponse
import urllib.request
import json
import ssl

# Create your views here.
def test_connect_issuer(request):

	#Do not use normal certificate
	# calee certificate made by me and verified by a trusted authority
	context = ssl._create_unverified_context()
	url = 'https://127.0.0.1/accounts/req_cred'
	response =  urllib.request.urlopen(url, context).read()
	data = {
        'objective': 'Test Connection',
        'other server response': json.loads(response)
    }
	return JsonResponse(data)


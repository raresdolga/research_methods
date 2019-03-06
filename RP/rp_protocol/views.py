from django.shortcuts import render
from django.http import JsonResponse
import urllib.request
import json
import ssl

# Create your views here.
def test_connect_issuer(request):

	#Do not use normal certificate, specify self signed certificate
	# calee certificate made by me and NOT verified by a trusted authority
	cert_path = "/etc/apache2/ssl/apache.crt";
	url = 'https://127.0.0.1/accounts/test_conn'
	response =  urllib.request.urlopen(url, cafile=cert_path)
	content =  response.read().decode(response.headers.get_content_charset())
	data = {
        'objective': 'Test Connection',
        'other server response':content
    }
	return JsonResponse(data)


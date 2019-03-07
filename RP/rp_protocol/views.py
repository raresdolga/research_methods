from django.shortcuts import render
from django.http import JsonResponse
import urllib.request
import json
import ssl

# Have a look at django-rest api. 
# For an example of django-rest token authentication configuration
# look in issuer



#==================Functions used for testing connection=================

""" Functions used for mannual tests of connection between 2 servers.
	Do not respect the design of our system, but do not delete them yet.
	Use the endpoints defined by this functions for quick testing
	Examples of how to handle or send requests. 
	Look in issue_protocol/urls.py to see how the paths of the views
"""

def example_token_issuer(request):
	""" Test connection with issuer endpoints that require token
	authnetication.
		Token was taken by post request accounts/get_token on issuer
		In real implementation user backend must store the token 
	in a session or somehow. If token is lost user can request again. 
	"""
	
	#Do not use normal certificate, specify self signed certificate
	# callee certificate made by me and NOT verified by a trusted authority
	cert_path = "/etc/apache2/ssl/apache.crt";
	url = 'https://127.0.0.1/accounts/test_conn'
	req = urllib.request.Request(url)
	req.add_header('Authorization', 'Token 7e4470cb4efdc5e8657e3746413c73430465e838')
	response =  urllib.request.urlopen(req, cafile=cert_path)
	content =  response.read().decode(response.headers.get_content_charset())
	data = {
        'objective': 'Test Connection',
        'other server response':content
    }
	return JsonResponse(data)


def test_connect_issuer(request):
	""" Test connection with issuer without token.
		Must get 401 Error 
	"""
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

#@api_view(['GET'])
#@permission_classes((AllowAny,))
def test_ledger(request):
	""" Test connection with the ledger
		Not working yet
	"""
	cert_path = "/etc/apache2/ssl/apache.crt";
	url = 'http://51.145.54.197:3000/api/org.example.biznet.CredentialCard'
	
	data_j = {
	  "$class": "org.example.biznet.CredentialCard",
	  "credId": "string",
	  "cardDescription": "string",
	  "active": True
	}
	data = urllib.parse.urlencode(data_j).encode( "utf8" )
	req = urllib.request.Request(url, data=data, headers={'content-type': 'application/json'})
	response =  urllib.request.urlopen(req)
	content =  response.read().decode(response.headers.get_content_charset())
	return JsonResponse(data)
import urllib.request
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view

from rp_protocol.crypto import Signature
from rp_protocol.forms import SessionIDForm
from rp_protocol.helpers import check_policy_format, verify_policy
from rp_protocol.models import UserSessionID, DummyCredential
from rp_protocol.policies import PresentationPolicy
from rp_protocol.serializers import UserSerializer, CredentialSerializer

# ==================Functions used for testing connection=================


# Have a look at django-rest api.
# For an example of django-rest token authentication configuration
# look in issuer

""" 
    Functions used for manual tests of connection between 2 servers.
	Do not respect the design of our system, but do not delete them yet.
	Use the endpoints defined by this functions for quick testing
	Examples of how to handle or send requests. 
	Look in issue_protocol/urls.py to see how the paths of the views
"""


def example_token_issuer(request):
    """
        Test connection with issuer endpoints that require token
        authentication.
        Token was taken by post request accounts/get_token on issuer
        In real implementation user backend must store the token
        in a session or somehow. If token is lost user can request again.
    """

    # Do not use normal certificate, specify self signed certificate
    # callee certificate made by me and NOT verified by a trusted authority
    cert_path = "/etc/apache2/ssl/apache.crt"
    url = 'https://127.0.0.1/accounts/test_conn'
    req = urllib.request.Request(url)
    req.add_header('Authorization', 'Token 7e4470cb4efdc5e8657e3746413c73430465e838')
    response = urllib.request.urlopen(req, cafile=cert_path)
    content = response.read().decode(response.headers.get_content_charset())
    data = {
        'objective': 'Test Connection',
        'other server response': content
    }
    return JsonResponse(data)


def test_connect_issuer(request):
    """ Test connection with issuer without token.
        Must get 401 Error
    """
    # Do not use normal certificate, specify self signed certificate
    # callee certificate made by me and NOT verified by a trusted authority
    cert_path = "/etc/apache2/ssl/apache.crt"
    url = 'https://127.0.0.1/accounts/test_conn'
    response = urllib.request.urlopen(url, cafile=cert_path)
    content = response.read().decode(response.headers.get_content_charset())
    data = {
        'objective': 'Test Connection',
        'other server response': content
    }
    return JsonResponse(data)


# @api_view(['GET'])
# @permission_classes((AllowAny,))
def test_ledger(request):
    """ Test connection with the ledger
        Not working yet
    """
    cert_path = "/etc/apache2/ssl/apache.crt"
    url = 'http://51.145.54.197:3000/api/org.example.biznet.CredentialCard'

    data_j = {
        "$class": "org.example.biznet.CredentialCard",
        "credId": "string",
        "cardDescription": "string",
        "active": True
    }
    data = urllib.parse.urlencode(data_j).encode("utf8")
    req = urllib.request.Request(url, data=data, headers={'content-type': 'application/json'})
    response = urllib.request.urlopen(req)
    content = response.read().decode(response.headers.get_content_charset())
    return JsonResponse(data)

# ==================Functions used in the Relying Party API=================


def home(request):
    return render(request, 'html/instructions.html', {}, status=status.HTTP_200_OK)


@api_view(['GET', 'POST'])
def request_access(request):
    if request.method == 'POST':

        # Create form
        form = SessionIDForm(request.POST)

        # If valid save sessionID to the database
        if form.is_valid():
            sessionID = UserSessionID(form.cleaned_data.get('sessionID'))

            # Check if sessionID is already in use
            if UserSessionID.objects.filter(pk=sessionID.sessionID).exists():
                return render(request, 'forms/sessionIDForm.html',
                              {'message': "The sessionID was not unique, try again: ", 'form': form}, status=status.HTTP_200_OK)
            else:
                sessionID.save()
                policy = PresentationPolicy(sessionID.sessionID)
                return JsonResponse(policy.get_policy(), status=status.HTTP_201_CREATED)
        else:
            return HttpResponse("Oops, something went wrong.", status=status.HTTP_400_BAD_REQUEST)
    else:
        form = SessionIDForm()
    return render(request, 'forms/sessionIDForm.html', {'message':"Please enter a unique ",'form': form}, status=status.HTTP_200_OK)


@api_view(['GET', 'POST'])
def present_credentials(request):
    if request.method == 'POST':
        if verify_policy(request.data):
            return JsonResponse(request.data)
        else:
            return HttpResponse("Didn't match")
    else:
        return HttpResponse("Test")


@api_view(['GET'])
def put_all(request):
    if request.method == 'GET':
        serializer = UserSerializer(UserSessionID.objects.all(), many=True)
        data = serializer.data
        return JsonResponse(data=data, safe=False)


@api_view(['GET'])
def delete_all(request):
    if request.method == 'GET':
        UserSessionID.objects.all().delete()
        return HttpResponse("Thanks")
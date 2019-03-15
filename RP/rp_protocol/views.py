import urllib.request
from uuid import uuid4

from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view

from rp_protocol.crypto import Signature
from rp_protocol.helpers import verify_policy
from rp_protocol.models import UserPolicyInformation
from rp_protocol.serializers import PolicySerializer

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


@api_view(['GET', 'POST'])
def test_verification(request):
    if request.method == 'POST':
        return JsonResponse(request.data)



# ==================Functions used in the Relying Party API=================


def home(request):
    return render(request, 'html/instructions.html', {}, status=status.HTTP_200_OK)


@api_view(['GET'])
def request_access(request):
    if request.method == 'GET':

        # TODO: remove after testing
        sig = Signature()

        # Create New PolicyInformation object with unique uuid
        new_session = UserPolicyInformation(sessionID=uuid4().hex, accepted_policies=sig.pub_key)

        # TODO: remove after testing
        s = sig.sign_message(new_session.sessionID.__str__())
        print("SessionID", new_session.sessionID)
        print("Pub: ", sig.pub_key)
        print("Sig: ", s)

        # Check if sessionID is already in use
        if UserPolicyInformation.objects.filter(pk=new_session.sessionID).exists():
            return HttpResponse(data="Couldn't generate a unique uuid, please try again",
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            new_session.save()
            data = PolicySerializer(new_session).data
            return JsonResponse(data=data, status=status.HTTP_201_CREATED)
    else:
        return HttpResponse(data="Please submit a GET request to this path", status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def verify_session(request):
    if request.method == 'POST':
        if verify_policy(request.data):
            return HttpResponse("Success")
        else:
            return HttpResponse("Your signatures didn't match")
    else:
        return HttpResponse("Wrong request")


# ==================Functions used for debuggging the Relying Party API=================


@api_view(['GET'])
def put_all(request):
    if request.method == 'GET':
        serializer = PolicySerializer(UserPolicyInformation.objects.all(), many=True)
        data = serializer.data
        return JsonResponse(data=data, safe=False)


@api_view(['GET'])
def delete_all(request):
    if request.method == 'GET':
        UserPolicyInformation.objects.all().delete()
        return HttpResponse("Thanks")

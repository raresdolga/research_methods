from django.shortcuts import render
from django.http import HttpRequest
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
import requests

#from issue_protocol.crypto_modules import Signature

logger = logging.getLogger(__name__)
#one signature setup - use just one set of keys
#sign_algh = Signature()

@csrf_exempt
def index(request):
    if(request.method == 'POST'):
        data = request.POST
        print(data)
        try:
            if data['password1'] == data['password2']:
                response = requests.post("http://localhost:8000/accounts/signup", data = dict(data.lists()))
                if response.status_code != HTTP_200_OK:
                    raise ValueError("Failed to signup")
                    # return HttpResponse("Failed to signup")
                else:
                    # login_req = HttpRequest()
                    # login_req.method = 'POST'
                    # login_req.META = request.META
                    
                    login_req_body = {}
                    login_req_body['username'] = data['username']
                    login_req_body['password'] = data['password1']

                    # login_req.POST = login_req_body 

                    #ready to do request to to login_api

                    try:
                        tokenResponse = requests.post("http://localhost:8000/accounts/get_token", data = login_req_body)
                        # print("Bazinga")
                        if tokenResponse.status_code == HTTP_200_OK:
                            # login()
                            token = json.loads(tokenResponse.text)['token']
                            # return redirect('user:front_page', token = token)
                            return HttpResponse(token)
                    except Exception as e:
                        return HttpResponse(str(e))
                             

        except Exception as e:
            response  = str(e)
        return HttpResponse(response)
    else:
        form = UserCreationForm()
        return render(request, 'registration/signup.html', {'form': form})


def login_view(request):
    if(request.method == 'POST'):
        data = request.POST
        try:
            response = requests.post("http://localhost:8000/accounts/get_token", data = dict(data.lists()))
            if response.status_code == HTTP_200_OK:
                token = json.loads(response.text)['token']
                return redirect('user:front_page', token = token)
                return HttpResponse(token)
        except Exception as e:
            response =  str(e)      
        return HttpResponse(response)
    else:
        form = AuthenticationForm()
    
    return render(request, 'registration/login.html', {'form': form})


def front_page(request, token = None):
    if request.method == "GET":
        if token == None:
            return HttpResponse("Sorry, you don't have a valid token man")
        else:
            return HttpResponse("You do have a valid token")
    return HttpResponse(request)


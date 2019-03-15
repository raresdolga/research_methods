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
import ast

import petlib
from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from os import urandom
from binascii import hexlify, unhexlify

from .models import PublicPrivateKeys, Token, newToken

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
                else:
                    
                    try:
                        login(request, user)
                        user = ast.literal_eval(response.content)['userId']
                    except Exception as e:
                        return HttpResponse(str(e))

                    login_req_body = {}
                    login_req_body['username'] = data['username']
                    login_req_body['password'] = data['password1']

                    #ready to do request to to login_api

                    try:
                        tokenResponse = requests.post("http://localhost:8000/accounts/get_token", data = login_req_body)
                        if tokenResponse.status_code == HTTP_200_OK:
                            token = json.loads(tokenResponse.text)['token']
                            request.META['token'] = token
                            return redirect("user:front_page")

                            return HttpResponse(token)
                    except Exception as e:
                        return HttpResponse(str(e))
                             

        except Exception as e:
            response  = str(e)
        return HttpResponse(response)
    else:
        form = UserCreationForm()
        return render(request, 'registration/signup.html', {'form': form})

@csrf_exempt
def login_view(request):
    if(request.method == 'POST'):
        data = request.POST
        try:
            response = requests.post("http://localhost:8000/accounts/get_token", data = dict(data.lists()))
            if response.status_code == HTTP_200_OK:
                try:
                    entry = newToken.objects.get(user = data['username'])
                except Exception as e :
                    token = newToken(token = json.loads(response.text)['token'], user = data['username'])
                    token.save()

                return redirect('/user/front_page/' + data['username'])
                #return HttpResponse(token)
        except Exception as e:
            response =  str(e)      
        return HttpResponse(response)
    else:
        form = AuthenticationForm()
    
    return render(request, 'registration/login.html', {'form': form})


def front_page(request, user = None):
    token = newToken.objects.get(user = user).token
    
    if token == None:
        return HttpResponse("You don't have a valid token")
    
    public_keys = []
    private_keys = []
    G = EcGroup()
    if(request.method == 'POST'):
        for i in range(4):
            priv = G.order().random()
            public = priv * G.generator()

            p1 = public.export()
            str_p1 = hexlify(p1).decode()
            public_keys.append(str_p1)

            #p2 = priv.export()
            str_p2 = priv.hex()
            private_keys.append(str_p2)

            #Groups.groups.append(G)
            #PrivateKeys.keys.append(str(priv))
            #PublicKeys.keys.append(str(public))
        

        data = {}
        #data['pub_keys'] = ["0354623943xxx282032-23", "12121", "12x01","88708042347237423093685-604968362"]
        data['pub_keys'] = public_keys
        data['attributes'] = {}

        # data['attributes']['name'] = request.POST['name']
        # data['attributes']['age'] = request.POST['age']
        # data['attributes']['City'] = request.POST['City']
        # data['policy'] = request.POST['policy']

        data['attributes']['name'] = 'user1'
        data['attributes']['age'] = '30'
        data['attributes']['City'] = 'London'
        data['policy_info'] = 'policy1'
        
        policy = 'policy1'
        str_public_keys = json.dumps(public_keys)
        str_private_keys = json.dumps(private_keys)

        pub_priv_batch = PublicPrivateKeys(public_keys = str_public_keys, private_keys = str_private_keys, policy = policy)

        cert_path = "/etc/apache2/ssl/apache.crt"
        url = 'http://127.0.0.1:8000/accounts/get_credential'
        data = urllib.parse.urlencode(data).encode( "utf-8" )

        req = urllib.request.Request(url, data=data, headers={'Authorization': 'Token ' + token})
        response =  urllib.request.urlopen(req)
        content =  response.read().decode('utf-8')

        if response.status == HTTP_200_OK:
            return HttpResponse("Created a credential")
            jsonResponse =  json.loads(response.text)
            if jsonResponse['valid'] == False:
                return HttpResponse(jsonResponse['invalid attributes'])
            else:
                return HttpResponse("We got a credential")
        else:
            return HttpResponse("Status code is not ok")
    

    else:
        form = AuthenticationForm()
        return render(request, 'registration/front_page.html', {'form': form})




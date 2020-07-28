from django.http import HttpResponse, HttpResponseRedirect, HttpRequest
from django.shortcuts import render
from django.urls import reverse
import bbrest
from bbrest import BbRest
import jsonpickle
import json
import os
import uuid

try:
    print("VIEWS.py: using config.py...")
    from config import adict

    KEY = adict['learn_rest_key']
    SECRET = adict['learn_rest_secret']
    LEARNFQDN = adict['learn_rest_fqdn']

except:
    print("VIEWS.py: using docker-compose env settings...")
    
    KEY = os.environ['APPLICATION_KEY']
    SECRET = os.environ['APPLICATION_SECRET']
    LEARNFQDN = os.environ['BLACKBOARD_LEARN_INSTANCE']

def isup(request):
    return renderer(request, 'isup.html')

def index(request):
    bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    resp = bb.GetVersion()
    access_token = bb.token_info['access_token']
    version_json = resp.json()

    context = {
        'learn_server': LEARNFQDN,
        'version_json' : version_json,
        'access_token' : access_token,
    }

    # Render the HTML template index.html with the data in the context variable
    return render(request, 'index.html', context=context)
from django.http import HttpResponse, HttpResponseRedirect, HttpRequest
from django.shortcuts import render
from django.urls import reverse
import bbrest
from bbrest import BbRest
import jsonpickle
import json
import os
import uuid

def index(request):
    

    # Render the HTML template index.html with the data in the context variable
    return render(request, 'index.html')
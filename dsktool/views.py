from django.http import HttpResponse, HttpResponseRedirect, HttpRequest
from django.shortcuts import render
from django.urls import reverse
import bbrest
from bbrest import BbRest
import jsonpickle
import json
import os
import uuid

def isup(request):
    return render(request, 'isup.html')

def index(request):
    """View function for home page of site."""

    # The following gets/stores the object to access Learn in the user's session.
    # This is key for 3LO web applications so that when you use the app, your
    # session has your object for accessing 
    

    # Render the HTML template index.html with the data in the context variable
    return render(request, 'index.html')

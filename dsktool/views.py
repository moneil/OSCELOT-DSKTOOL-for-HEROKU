from django.http import HttpResponse, HttpResponseRedirect, HttpRequest
from django.shortcuts import render
from django.urls import reverse


def index(request):
    

    # Render the HTML template index.html with the data in the context variable
    return render(request, 'index.html')
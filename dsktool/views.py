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
    from config import adict
    
    print("VIEWS: using config.py...")

    KEY = adict['learn_rest_key']
    SECRET = adict['learn_rest_secret']
    LEARNFQDN = adict['learn_rest_fqdn']

except:
    print("VIEWS: using docker-compose env settings...")
    
    KEY = os.environ['APPLICATION_KEY']
    SECRET = os.environ['APPLICATION_SECRET']
    LEARNFQDN = os.environ['BLACKBOARD_LEARN_INSTANCE']

print("VIEWS: KEY: ", KEY)
print("VIEWS: SECRET: ", SECRET)
print("VIEWS: LEARNFQDN: ", LEARNFQDN)

def isup(request):
    return render(request, 'isup.html')

def index(request):
    bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    resp = bb.GetVersion()
    access_token = bb.token_info['access_token']
    version_json = resp.json()

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print("VIEWS: index request: pickled BbRest and putting it on session")
        request.session['bb_json'] = bb_json
        request.session['target_view'] = 'index'
        return HttpResponseRedirect(reverse('get_auth_code'))
    else:
        print('VIEWS: index request: got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('VIEWS.py: index request: expired token')
            request.session['bb_json'] = None
            index(request)
        bb.supported_functions() 
        bb.method_generator()
        print(f'VIEWS: index request: expiration: {bb.expiration()}')

    context = {
        'learn_server': LEARNFQDN,
        'version_json' : version_json,
        'access_token' : access_token,
    }

    return render(request, 'index.html', context=context)

def whoami(request):
    """View function for whoami page of site."""
    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        request.session['target_view'] = 'whoami' # So after we have the access token we know to come back here.
        # The following does maintain the https: scheme if that was used with the incomming request.
        # BUT because I'm terminating the tls at the ngrok server, my incomming request is http.
        # Hence the redirect to get_auth_code is http in development. But we want our redirect_uri to be
        # have a scheme of https so that the Learn server can redirect back through ngrok with our 
        # secure SSL cert. We'll have to build a redirect_uri with the https scheme in the 
        # get_auth_code function.
    
        return HttpResponseRedirect(reverse('get_auth_code'))
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
            whoami(request)
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    resp = bb.call('GetUser', userId = "me", params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, dataSourceId, created'}, sync=True ) #Need BbRest to support "me"
    
    user_json = resp.json()

    dskresp = bb.call('GetDataSource', dataSourceId = user_json['dataSourceId'], sync=True)
    dsk_json = dskresp.json()

    user_json['dataSourceId'] = dsk_json['externalId']

    context = {
        'user_json': user_json,
        'access_token': bb.token_info['access_token']
    }

    # Render the HTML template index.html with the data in the context variable
    return render(request, 'whoami.html', context=context)

def notauthorized(request):
    context = {}
    return render(request, 'notauthorized.html', context=context )

def learnlogout(request):
    print("VIEWS.py: index request: Flushing session and redirecting to Learn for logout")
    request.session.flush()
    return HttpResponseRedirect(f"https://{LEARNFQDN}/webapps/login?action=logout")

def sortDsk(dsks):
  return sorted(dsks, key=lambda x: x['externalId'])

def get_auth_code(request):
    # Happens when the user hits index the first time and hasn't authenticated on Learn
    # Part I. Request an authroization code oauth2/authorizationcode
    print(f"In get_auth_code: REQUEST URI:{request.build_absolute_uri()}")
    bb_json = request.session.get('bb_json')
    print('got BbRest from session')
    bb = jsonpickle.decode(bb_json)
    bb.supported_functions() # This and the following are required after
    bb.method_generator()    # unpickling the pickled object. 
    # The following gives the path to the resource on the server where we are running, 
    # but not the protocol or host FQDN. We need to prepend those to get an absolute redirect uri.
    redirect_uri = reverse(get_access_token)
    absolute_redirect_uri = f"https://{request.get_host()}{redirect_uri}"
    state = str(uuid.uuid4())
    request.session['state'] = state
    authcodeurl = bb.get_auth_url(redirect_uri=absolute_redirect_uri, state=state)

    print(f"AUTHCODEURL:{authcodeurl}")
    return HttpResponseRedirect(authcodeurl)

def get_access_token(request):
    # Happens when the user hits index the first time and hasn't authenticated on Learn
    # Part II. Get an access token for the user that logged in. Put that on their session.
    bb_json = request.session.get('bb_json')
    target_view = request.session.get('target_view')
    print('VIEWS: get_access_token: got BbRest from session')
    bb = jsonpickle.decode(bb_json)
    bb.supported_functions() # This and the following are required after
    bb.method_generator()    # unpickling the pickled object.
    # Next, get the code parameter value from the request
    redirect_uri = reverse(get_access_token)
    absolute_redirect_uri = f"https://{request.get_host()}{redirect_uri}"

    state = request.GET.get('state', default= "NOSTATE")
    print(f'VIEWS: get_access_token: GOT BACK state: {state}')
    stored_state = request.session.get('state')
    print(f'VIEWS: get_access_token: STORED STATE: {stored_state}')
    if (stored_state != state):
        return HttpResponseRedirect(reverse('notauthorized'))

    code =  request.GET.get('code', default = None)
    if (code == None):
        exit()
    #Rebuild a new BbRest object to get an access token with the user's authcode.
    user_bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}", code=code, redirect_uri=absolute_redirect_uri )
    bb_json = jsonpickle.encode(user_bb)
    print('VIEWS: get_access_token: pickled BbRest and putting it on session')
    request.session['bb_json'] = bb_json
    return HttpResponseRedirect(reverse(f'{target_view}'))

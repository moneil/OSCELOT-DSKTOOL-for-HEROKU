from django.http import HttpResponse, HttpResponseRedirect, HttpRequest
from django.shortcuts import render
from django.shortcuts import redirect
from django.urls import reverse
import bbrest
from bbrest import BbRest
import jsonpickle
import json
import os
import uuid

from django.http import JsonResponse
#from django.views.generic import View
#from django.views.decorators.csrf import csrf_exempt
#from django.utils.decorators import method_decorator
#from django.forms.models import model_to_dict
#from django.shortcuts import render

try:
    from config import adict
    
    print("VIEWS: using config.py...")

    KEY = adict['APPLICATION_KEY']
    SECRET = adict['APPLICATION_SECRET']
    LEARNFQDN = adict['BLACKBOARD_LEARN_INSTANCE']

except:
    print("VIEWS: using env settings...")
    
    KEY = os.environ['APPLICATION_KEY']
    SECRET = os.environ['APPLICATION_SECRET']
    LEARNFQDN = os.environ['BLACKBOARD_LEARN_INSTANCE']

ISGUESTUSER = False

# print("VIEWS: KEY: ", KEY)
# print("VIEWS: SECRET: ", SECRET)
# print("VIEWS: LEARNFQDN: ", LEARNFQDN)

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

    if ISGUESTUSER:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )
 
    context = {
        'learn_server': LEARNFQDN,
        'version_json' : version_json,
        'access_token' : access_token,
    }

    return render(request, 'index.html', context=context)

def courses(request):
    task = request.GET.get('task')
    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)
    print ("TASK: ", task)

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        request.session['target_view'] = 'courses'
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

    if ISGUESTUSER:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )    

    if (task == 'search'):
        #Process request...
        print (f"COURSE REQUEST: ACTION {task}")
        searchValue = request.GET.get('searchValue')
        if (searchValue is not None):
            searchValue = searchValue.strip()
        
        print (f"COURSE REQUEST: CRS: {searchValue}")
        print (f"Process by {searchBy}")
        if (searchBy == 'externalId'):
            crs="externalId:" + searchValue
            print(f"course pattern: {crs}")
        elif (searchBy == 'primaryId'):
            crs=searchValue
            print(f"course pattern: {crs}")
        elif (searchBy == 'courseId'):
            crs="courseId:" + searchValue
            print(f"course pattern: {crs}")
        resp = bb.GetCourse(courseId = crs, params = {'fields':'id, courseId, externalId, name, availability.available, dataSourceId, created'}, sync=True )
        if (resp.status_code == 200):
            course_json = resp.json() 
            dskresp = bb.GetDataSource(dataSourceId = course_json['dataSourceId'], sync=True)
            dsk_json = dskresp.json()
            course_json['dataSourceId'] = dsk_json['externalId']
            course_json['searchValue'] = searchValue
            course_json['searchBy'] = searchBy
            dskresp = bb.GetDataSources(params={'fields':'id, externalId'}, sync=True)
            dsks_json = dskresp.json()
            print ("DSKS:\n", dsks_json["results"])
            dsks = dsks_json["results"]
            dsks = sortDsk(dsks)
            print ("SIZE OF DSK LIST:", len(dsks))
                
            context = {
              'course_json': course_json,
              'dsks_json': dsks,
            }
        else:
            error_json = resp.json()
            print (f"RESPONSE:\n", error_json)
            context = {
                'error_json': error_json,
            }

        return render(request, 'courses.html', context=context)

    if (task == 'process'):
        print (f"COURSE REQUEST: ACTION {task}")
        print (f"Process by {searchBy}")
        print ('Request:\n ')
        print (request)
        payload={}
        if (request.GET.get('isAvailabilityUpdateRequired1')):
            if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                payload={'availability':{"available":request.GET.get('selectedAvailability')}}
        if (request.GET.get('isDataSourceKeyUpdateRequired1')):
            if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                payload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
            
        print ("PAYLOAD\n")
        for x, y in payload.items():
            print(x, y)

        # Build and make bb request...
        if (searchBy == 'externalId'):
            crs="externalId:" + searchValue
        elif (searchBy == 'primaryId'):
            crs=searchValue
            print(f"course pattern: {crs}")
        elif (searchBy == 'courseId'):
            crs="courseId:" + searchValue
            print(f"course pattern: {crs}")

        print(f"course pattern: {crs}")

        resp = bb.UpdateCourse(courseId = crs, payload=payload, params = {'fields':'id, courseId, externalId, name, availability.available, dataSourceId, created'}, sync=True )
        if (resp.status_code == 200):
            result_json = resp.json() #return actual error
            dskresp = bb.GetDataSource(dataSourceId = result_json['dataSourceId'], sync=True)
            dsk_json = dskresp.json()
            result_json['dataSourceId'] = dsk_json['externalId']

            context = {
              'result_json': result_json,
            }
        else:
            error_json = resp.json()
            print (f"RESPONSE:\n", error_json)
            context = {
                'error_json': error_json,
            }

        return render(request, 'courses.html', context=context)

    return render(request, 'courses.html')

def enrollments(request):
    task = request.GET.get('task')
    searchBy = request.GET.get('searchBy')

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        request.session['target_view'] = 'whoami' 
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

    if ISGUESTUSER:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )
     
    if (task == 'search'):
        #Process request...
        print (f"ENROLLMENTS REQUEST: ACTION {task}")
        searchValueCrs = request.GET.get('searchValueCrs')
        if (searchValueCrs is not None):
            searchValueCrs = searchValueCrs.strip()
        searchValueUsr = request.GET.get('searchValueUsr')
        if (searchValueUsr is not None):
            searchValueUsr = searchValueUsr.strip()
        print (f"ENROLLMENTS REQUEST: CRS: {searchValueCrs}")
        print (f"ENROLLMENTS REQUEST: USR: {searchValueUsr}")

        if (searchBy == 'byCrsUsr'):
            print ("Process by Course AND User")
            crs="externalId:" + searchValueCrs
            usr="externalId:" + searchValueUsr
            resp = bb.GetMembership(courseId=crs, userId = usr, params = {'expand':'user', 'fields':'id, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email, availability.available, user.availability.available, dataSourceId, created'}, sync=True )
            if (resp.status_code == 200):
                member_json = resp.json() 
                print ("MBRJSON:\n", member_json["results"])

                dskresp = bb.GetDataSource(dataSourceId = member_json['dataSourceId'], sync=True)
                dsk_json = dskresp.json()
                member_json['dataSourceId'] = dsk_json['externalId']
                member_json['crsExternalId'] = searchValueCrs
                member_json['usrExternalId'] = searchValueUsr
                member_json['searchBy'] = searchBy
                dskresp = bb.GetDataSources(params={'fields':'id, externalId'}, sync=True)
                dsks_json = dskresp.json()
                print ("DSKS:\n", dsks_json["results"])
                dsks = dsks_json["results"]
                dsks = sortDsk(dsks)
                print ("SIZE OF DSK LIST:", len(dsks))
                
                context = {
                  'member_json': member_json,
                  'dsks_json': dsks,
                }
            else:
                error_json = resp.json()
                print (f"RESPONSE:\n", error_json)
                context = {
                    'error_json': error_json,
                }

            return render(request, 'enrollments.html', context=context)

        elif (searchBy == 'byCrs'):
            print ("Process by Course Only")
            error_json = {
                'message': 'Searching by Course is not currently supported'
            }
            print (f"RESPONSE:\n", error_json)
            context = {
                'error_json': error_json,
            }
            return render(request, 'enrollments.html', context=context)

        elif (searchBy == 'byUsr'):
            print ("Process by User Only")
            error_json = {
                'message': 'Searching by Course is not currently supported'
            }
            print (f"RESPONSE:\n", error_json)
            context = {
                'error_json': error_json,
            }
            return render(request, 'enrollments.html', context=context)

        else: 
            print ("Cannot process request")
            error_json = {
                'message': 'Cannot process request'
            }
            print (f"RESPONSE:\n", error_json)
            context = {
                'error_json': error_json,
            }
            return render(request, 'enrollments.html', context=context)


    elif (task == 'process'):
        # print incoming parameters and then afterward submit the patch request.
        
        if (searchBy == 'byCrsUsr'):
            print ("processing by crsusr")
            print ('Request:\n ')
            print (request)

            payload={}
            if (request.GET.get('isAvailabilityUpdateRequired1')):
                if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                    payload={'availability':{"available":request.GET.get('selectedAvailability')}}
            if (request.GET.get('isDataSourceKeyUpdateRequired1')):
                if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                    payload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
            
            print ("PAYLOAD\n")
            for x, y in payload.items():
                print(x, y)

            # Build and make bb request...
            crs = "externalId:"+request.GET.get('crsExternalId')
            print ("crs:", crs)
            usr = "externalId:"+request.GET.get('usrExternalId')
            print ("usr", usr)

            resp = bb.UpdateMembership(courseId=crs, userId = usr, payload=payload, params = {'expand':'user', 'fields':'id, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email, availability.available, user.availability.available, dataSourceId, created'}, sync=True )
            if (resp.status_code == 200):
                result_json = resp.json() #return actual error
                dskresp = bb.GetDataSource(dataSourceId = result_json['dataSourceId'], sync=True)
                dsk_json = dskresp.json()
                result_json['dataSourceId'] = dsk_json['externalId']

                context = {
                  'result_json': result_json,
                }
            else:
                error_json = resp.json()
                print (f"RESPONSE:\n", error_json)
                context = {
                    'error_json': error_json,
                }

            return render(request, 'enrollments.html', context=context)


            # crs="externalId:" + searchValueCrs
            # usr="externalId:" + searchValueUsr
            # resp = bb.UpdateMembership(courseId=crs, userId = usr, params = {'expand':'user', 'fields':'id, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email, availability.available, user.availability.available, dataSourceId, created'}, sync=True )
            # if (resp.status_code == 200):
            #     member_json = resp.json() #return actual error
            #     dskresp = bb.GetDataSource(dataSourceId = member_json['dataSourceId'], sync=True)
            #     dsk_json = dskresp.json()
            #     member_json['dataSourceId'] = dsk_json['externalId']
            #     member_json['crsExternalId'] = searchValueCrs
            #     member_json['searchBy'] = searchBy
            #     dskresp = bb.GetDataSources(params={'fields':'id, externalId'}, sync=True)
            #     dsks_json = dskresp.json()
            #     print ("DSKS:\n", dsks_json["results"])
            #     print ("SIZE OF DSK LIST:", len(dsks_json["results"]))
                
            #     context = {
            #       'member_json': member_json,
            #       'dsks_json': dsks_json["results"],
            #     }
            # else:
            #     error_json = resp.json()
            #     print (f"RESPONSE:\n", error_json)
            #     context = {
            #         'error_json': error_json,
            #     }

            #return render(request, 'enrollments.html', context=context)

        result_json = {"brand": "Ford", "model": "Mustang", "year": 1964 }

        print (f"RESPONSE:\n", result_json)

        context = {     
            'result_json': result_json,
        }

        return render(request, 'enrollments.html', context=context)

    else:
        return render(request, 'enrollments.html')

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
    # if (CUSTOM_LOGIN_URL):
    #     print("CUSTOM_LOGIN_URL")
    #     user_bb = BbRest(KEY, SECRET, f"https://{CUSTOM_LOGIN_URL}", code=code, redirect_uri=absolute_redirect_uri )
    # else:
    user_bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}", code=code, redirect_uri=absolute_redirect_uri )    
    bb_json = jsonpickle.encode(user_bb)
    if (isGuestUser(bb_json)):
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )
        

    print('VIEWS: get_access_token: pickled BbRest and putting it on session')
    request.session['bb_json'] = bb_json
    return HttpResponseRedirect(reverse(f'{target_view}'))

def get_auth_code(request):
    # Happens when the user hits index the first time and hasn't authenticated on Learn
    # Part I. Request an authroization code oauth2/authorizationcode
    print(f"In get_auth_code: REQUEST URI:{request.build_absolute_uri()}")
    try: 
        bb_json = request.session.get('bb_json')
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
    except:
        #sideways sesssion go to index page and force get_access_token
        return HttpResponseRedirect(reverse('index'))


    bb.supported_functions() # This and the following are required after
    bb.method_generator()    # unpickling the pickled object. 
    # The following gives the path to the resource on the server where we are running, 
    # but not the protocol or host FQDN. We need to prepend those to get an absolute redirect uri.
    redirect_uri = reverse(get_access_token)
    absolute_redirect_uri = f"https://{request.get_host()}{redirect_uri}"
    state = str(uuid.uuid4())
    request.session['state'] = state
    authcodeurl = bb.get_auth_url(scope='read write', redirect_uri=absolute_redirect_uri, state=state)

    print(f"AUTHCODEURL:{authcodeurl}")
    return HttpResponseRedirect(authcodeurl)

def isup(request):
    return render(request, 'isup.html')

def logoutUser(request):
    print(f"VIEWS: LogoutUser: Site domain: {request.META['HTTP_HOST']}")
    site_domain = request.META['HTTP_HOST']
    response = HttpResponse("Cookies Cleared")
    if (request.COOKIES.get(site_domain) is not None):
    #if site_domain in request.COOKIES.keys():
        #response = HttpResponse("Cookies Cleared")
        print("VIEWS: LogoutUser: clearing cookies")
        response = redirect('/threeleg/learnlogout')
        response.delete_cookie(site_domain)
    else:
        print("VIEWS: LogoutUser: no cookies to clear")
        response = redirect('/threeleg/learnlogout')

    #response = HttpResponse("We are not tracking you.")
    return response

def learnlogout(request):
    print("VIEWS.py: index request: Flushing session and redirecting to Learn for logout")
    request.session.flush()

    return HttpResponseRedirect(f"https://{LEARNFQDN}/webapps/login?action=logout")

def notauthorized(request):
    context = {}
    return render(request, 'notauthorized.html', context=context )

def users(request):
    task = request.GET.get('task')
    searchBy = request.GET.get('searchBy')
    searchValueUsr = request.GET.get('searchValueUsr')
    if (searchValueUsr is not None):
        searchValueUsr = searchValueUsr.strip()
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUEUSR: ", searchValueUsr)
    print ("TASK: ", task)

    """View function for users page of site."""
    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        request.session['target_view'] = 'users'
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

    if ISGUESTUSER:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )
     
    if (task == 'search'):
        #Process request...
        print (f"USERS REQUEST: ACTION {task}")
        searchBy = request.GET.get('searchBy')
        searchValueUsr = request.GET.get('searchValue')
        if (searchValueUsr is not None):
            searchValueUsr = searchValueUsr.strip()
        print (f"USERS REQUEST: USR: {searchValueUsr}")
        print (f"Process by {searchBy}")
        if (searchBy == 'externalId'):
            usr="externalId:" + searchValueUsr
            print(f"user pattern: {usr}")
        elif (searchBy == 'userName'):
            usr="userName:" + searchValueUsr
            print(f"user pattern: {usr}")
        resp = bb.GetUser(userId = usr, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created'}, sync=True )
        if (resp.status_code == 200):
            user_json = resp.json() 
            dskresp = bb.GetDataSource(dataSourceId = user_json['dataSourceId'], sync=True)
            dsk_json = dskresp.json()
            user_json['dataSourceId'] = dsk_json['externalId']
            user_json['searchValueUsr'] = searchValueUsr
            user_json['searchBy'] = searchBy
            dskresp = bb.GetDataSources(params={'fields':'id, externalId'}, sync=True)
            dsks_json = dskresp.json()
            print ("DSKS:\n", dsks_json["results"])
            dsks = dsks_json["results"]
            dsks = sortDsk(dsks)
            print ("SIZE OF DSK LIST:", len(dsks))
                
            context = {
              'user_json': user_json,
              'dsks_json': dsks,
            }
        else:
            error_json = resp.json()
            print (f"RESPONSE:\n", error_json)
            context = {
                'error_json': error_json,
            }

        return render(request, 'users.html', context=context)

    if (task == 'process'):
        print (f"USERS REQUEST: ACTION {task}")
        print (f"Process by {searchBy}")
        print ('Request:\n ')
        print (request)
        payload={}
        if (request.GET.get('isAvailabilityUpdateRequired1')):
            if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                payload={'availability':{"available":request.GET.get('selectedAvailability')}}
        if (request.GET.get('isDataSourceKeyUpdateRequired1')):
            if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                payload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
            
        print ("PAYLOAD\n")
        for x, y in payload.items():
            print(x, y)

        # Build and make bb request...
        if (searchBy == 'externalId'):
            usr="externalId:" + searchValueUsr
        elif (searchBy == 'userName'):
            usr="userName:" + searchValueUsr

        print(f"user pattern: {usr}")

        resp = bb.UpdateUser(userId = usr, payload=payload, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created'}, sync=True )
        if (resp.status_code == 200):
            result_json = resp.json() #return actual error
            dskresp = bb.GetDataSource(dataSourceId = result_json['dataSourceId'], sync=True)
            dsk_json = dskresp.json()
            result_json['dataSourceId'] = dsk_json['externalId']

            context = {
              'result_json': result_json,
            }
        else:
            error_json = resp.json()
            print (f"RESPONSE:\n", error_json)
            context = {
                'error_json': error_json,
            }

        return render(request, 'users.html', context=context)

    return render(request, 'users.html')

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

    if ISGUESTUSER:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )
        
    resp = bb.call('GetUser', userId = "me", params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, dataSourceId, created'}, sync=True ) #Need BbRest to support "me"
    
    user_json = resp.json()

    #note: this next call is what is failing with 3LO on non-gateway logins
    #could probably just wrap the next three lines in a try/except statment 
    # - handing off to 'guestusernotallowed' if datasource call fails
    try:
        dskresp = bb.call('GetDataSource', dataSourceId = user_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        user_json['dataSourceId'] = dsk_json['externalId']
    except:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )

    context = {
        'user_json': user_json,
        'access_token': bb.token_info['access_token']
    }

    # Render the HTML template index.html with the data in the context variable
    return render(request, 'whoami.html', context=context)

def sortDsk(dsks):
  return sorted(dsks, key=lambda x: x['externalId'])

def isGuestUser(bb_json):
    guestStatus = False

    bb = jsonpickle.decode(bb_json)
    resp = bb.call('GetUser', userId = "me", params = {'fields':'userName'}, sync=True ) 
    
    user_json = resp.json()

    print(f"ISGUESTUSER::userName: {user_json['userName']}")

    if user_json['userName'] == 'guest':
        guestStatus = True
        ISGUESTUSER = True
    else:
        guestStatus = False
        ISGUESTUSER = False

    return guestStatus

def guestusernotallowed(request):
    context = {
        'learn_server': LEARNFQDN,
    }   
    return render(request, 'guestusernotallowed.html', context=context )

def error_500(request):
    data = {}
    return render(request,'error_500.html', data)

def updateCourseMemberships(request):
    finalResponse = {}
    print("request method: ", request.method)
    print("request: ", request)
    searchValue = request.GET.get("crsSearchValue")
    print("request searchValue: ", searchValue)
    searchBy = request.GET.get("crsSearchBy")
    print("request searchBy: ", searchBy)
    userArray =  request.GET.getlist('pmcUserId[]')
    print("request pmcUsersList: \n", userArray)

    if (searchBy == "externalId"):
        crs = "externalId:"+searchValue
        print ("COURSE TO UPDATE: ", crs)
    elif (searchBy == "courseId"):
        crs = "courseId:"+searchValue
        print ("COURSE TO UPDATE:", crs)

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        return HttpResponseRedirect(reverse('get_auth_code'))
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    dsks_json = bb.GetDataSources(params = {'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    resps = {'results':[]}
    print("RESPS SET TO EMPTY RESULTS")

    if (request.GET.get('isUpdateRequired1') == 'true'):
        print("isUpdateRequired1", request.GET.get('isUpdateRequired1'))

        for user in userArray:            
            payload={}
            if (request.GET.get('isAvailabilityUpdateRequired1')):
                print(user + ": isAvailabilityUpdateRequired1: ", request.GET.get('isAvailabilityUpdateRequired1'))

                if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                    payload={'availability':{"available":request.GET.get('selectedAvailability')}}
                    print(user + ": availability: ",request.GET.get('selectedAvailability'))

            if (request.GET.get('isDataSourceKeyUpdateRequired1')):
                print(user + ": isDataSourceKeyUpdateRequired1: ", request.GET.get('isDataSourceKeyUpdateRequired1'))
            
                if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                    payload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
                    print(user + ": dataSourceId: ",request.GET.get('selectedDataSourceKey'))
            
            print("PAYLOAD: \n", payload)

            resp = bb.UpdateMembership(courseId=crs, userId = user, payload=payload, params = {'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True )

            respJSON = resp.json()

            if (resp.status_code == 200):
                print("RESP:\n", resp.json())
                #resps["results"].append(respJSON["results"])
                print ("User:" + user + "UPDATED WITH PAYLOAD: \n", payload)
                print("RESPJSON:\n", respJSON)
                print("RESPJSON:dataSourceId", respJSON["dataSourceId"])

                for dsk in dsks:
                    #print("DSK:\n", dsk)
                    #print("DSKID: ", dsk["id"])
                    if (dsk["id"] == respJSON["dataSourceId"]):
                        print("DSKEXTERNALID: ", dsk["externalId"])
                        respJSON["dataSourceId"] = dsk["externalId"]
                        print("RESPJSON:dataSourceId", respJSON["dataSourceId"])

            else:
                error_json["results":] = resp.json()
                print("resp.status_code:", resp.status_code)
                print (f"RESPONSE:\n", error_json)

            resps["results"].append(respJSON)
            print("RESPS:\n", resps)
        
        finalResponse = {
            "updateList": userArray,
            "resps": resps,
        }

        print("FINAL RESPONSE:\n", finalResponse)
                   
    return JsonResponse(finalResponse)

def validate_userIdentifier(request):
    task = request.GET.get('task')
    searchBy = request.GET.get('searchBy') #externalId || userName
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print("LEARNFQDN", LEARNFQDN)
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)
    print ("TASK: ", task)
    
    if (searchBy == 'externalId'):
        usr = "externalId:" + searchValue
    else:
        usr = "userName:" + searchValue

    print(f"user pattern: {usr}")

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    
    validationresult = bb.GetUser(userId = usr, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created'}, sync=True )

    print("VALIDATIONRESULT_STATUS: ", validationresult.status_code)
    print(f"VALIDATIONRESULT:\n", validationresult.json())

    #Use asynchronous when processing requests
    # tasks = []
    # for user in users:
    #     tasks.append(bb.GetUser(user), sync=False)
    #     resps = await asynchio.gather(*tasks)

    if (validationresult.status_code == 200):
        foundStatus = True
    else:
        foundStatus = False
    
    data = {
        'is_found': foundStatus
    }

    return JsonResponse(data)

def validate_courseIdentifier(request):
    print("validate_courseIdentifier called....")
    task = request.GET.get('task')
    searchBy = request.GET.get('searchBy') #externalId || userName
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print("LEARNFQDN", LEARNFQDN)
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)
    print ("TASK: ", task)
    
    if (searchBy == 'externalId'):
        crs = "externalId:" + searchValue
    else:
        crs = "courseId:" + searchValue

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    
    validationresult = bb.GetCourse(courseId = crs, sync=True )

    print("VALIDATIONRESULT_STATUS: ", validationresult.status_code)
    print(f"VALIDATIONRESULT:\n", validationresult.json())

    if (validationresult.status_code == 200):
        foundStatus = True
    else:
        foundStatus = False
    
    data = {
        'is_found': foundStatus
    }

    return JsonResponse(data)

def getCourseMemberships(request):
    print("getCourseMembers Called...")
    print("request method: ", request.method)

    task = request.GET.get('task')
    searchBy = request.GET.get('searchBy') #externalId || userName
    searchValue = request.GET.get('searchValue')
    getThemAll = request.GET.get('getEmAll')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print("LEARNFQDN", LEARNFQDN)
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)
    print ("TASK: ", task)
    print ("GET EM ALL?: ", getThemAll)
    
    if (searchBy == 'externalId'):
        crs = "externalId:" + searchValue
    else:
        crs = "courseId:" + searchValue

    bb_json = request.session.get('bb_json')

    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    memberships_result = bb.GetCourseMemberships( courseId = crs, limit = 1500, params = {'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True )

    print("memberships_result status: ", memberships_result.status_code)
    membershipsResultJSON = memberships_result.json()
    print(f"\nmemberships_result:\n", membershipsResultJSON)

    if (memberships_result.status_code == 200):
        dsksResp = bb.GetDataSources(params = {'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        #print("DSKS_JSON: \n", dsks_json)
        dsks = dsks_json["results"]
        #print("DSKS: \n", dsks)
        dsks = sortDsk(dsks)
        #print("SORTEDDSKS: \n", dsks)
        
        for idx, membership in enumerate(membershipsResultJSON["results"]):
            print("\nMEMBERSHIP: ", membership["dataSourceId"])
            for dsk in dsks:
                #print("DSK:\n", dsk)
                #print("DSKID: ", dsk["id"])
                if (dsk["id"] == membership["dataSourceId"]):
                    print("DSKEXTERNALID: ", dsk["externalId"])
                    membershipsResultJSON["results"][idx]["dataSourceId"] = dsk["externalId"]
                    print(membershipsResultJSON["results"][idx]["dataSourceId"])
        
        print(f"\nmemberships_result AFTER:\n", membershipsResultJSON)

    #Use asynchronous when processing requests
    # tasks = []
    # for user in users:
    #     tasks.append(bb.GetUser(user), sync=False)
    #     resps = await asynchio.gather(*tasks)

    context = {
              'memberships_json': membershipsResultJSON,
              'dsks_json': dsks,
            }

    return JsonResponse(context)

# AJAX
# [DONE] Reduce error opportunity by validating form entered values
def validate_userIdentifier(request):
    searchBy = request.GET.get('searchBy') #externalId || userName
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print("validate_userIdentifier: LEARNFQDN", LEARNFQDN)
    print ("validate_userIdentifier: SEARCHBY: ", searchBy)
    print ("validate_userIdentifier: SEARCHVALUE: ", searchValue)
    
    if (searchBy == 'externalId'):
        usr = "externalId:" + searchValue
    else:
        usr = "userName:" + searchValue

    print(f"user pattern: {usr}")

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    
    validationresult = bb.GetUser(userId = usr, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created'}, sync=True )

    print("VALIDATIONRESULT_STATUS: ", validationresult.status_code)
    print(f"VALIDATIONRESULT:\n", validationresult.json())

    #Use asynchronous when processing requests
    # tasks = []
    # for user in users:
    #     tasks.append(bb.GetUser(user), sync=False)
    #     resps = await asynchio.gather(*tasks)

    if (validationresult.status_code == 200):
        foundStatus = True
    else:
        foundStatus = False
    
    data = {
        'is_found': foundStatus
    }

    return JsonResponse(data)
# [DONE] Reduce error opportunity by validating form entered values
def validate_courseIdentifier(request):
    print("validate_courseIdentifier called....")
    searchBy = request.GET.get('searchBy') #externalId || userName
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print("LEARNFQDN", LEARNFQDN)
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)
    
    if (searchBy == 'externalId'):
        crs = "externalId:" + searchValue
    elif (searchBy == 'primaryId'):
        crs=searchValue
    else:
        crs = "courseId:" + searchValue

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    
    validationresult = bb.GetCourse(courseId = crs, sync=True )

    print("VALIDATIONRESULT_STATUS: ", validationresult.status_code)
    print(f"VALIDATIONRESULT:\n", validationresult.json())

    if (validationresult.status_code == 200):
        foundStatus = True
    else:
        foundStatus = False
    
    data = {
        'is_found': foundStatus
    }

    return JsonResponse(data)
# [DONE] Retrieve a single course membership
def getCourseMembership(request):
    #Get a single course membership
    print("\ngetCourseMember Called...")
    print("request method: ", request.method)

    #{"searchByCrs":"externalId","searchValueCrs":"moneil-available","searchValueUsr":"moneil","searchByUsr":"externalId"}
    crsSearchBy = request.GET.get('crsSearchBy') #externalId || userName
    crsToSearchFor = request.GET.get('crsToSearchFor')
    usrSearchBy = request.GET.get('usrSearchBy') #externalId || userName
    usrToSearchFor = request.GET.get('usrToSearchFor')
    print("getCourseMembership::crsSearchBy", crsSearchBy)
    print ("getCourseMembership::crsToSearch: ", crsToSearchFor)
    print ("getCourseMembership::usrSearchBy: ", usrSearchBy)
    print ("getCourseMembership::usrToSearchFor", usrToSearchFor)

    if (crsSearchBy == 'externalId'):
        crs = "externalId:" + crsToSearchFor
    else:
        crs = "courseId:" + crsToSearchFor
    if (usrSearchBy == 'externalId'):
        usr = "externalId:" + usrToSearchFor
    else:
        usr = "userName:" + usrToSearchFor

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    membership_result = bb.GetMembership( courseId = crs, userId = usr, params = {'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, childCourseId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True )

    print("getCourseMembership::membership_result status: ", membership_result.status_code)

    if (membership_result.status_code == 200):
        member_json = membership_result.json() 
        print ("MBRJSON:\n", member_json)

        dskresp = bb.GetDataSource(dataSourceId = member_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        member_json['dataSourceId'] = dsk_json['externalId']
        member_json['crsToSearchFor'] = crsToSearchFor
        member_json['crsSearchBy'] = crsSearchBy
        member_json['usrToSearchFor'] = usrToSearchFor
        member_json['usrSearchBy'] = usrSearchBy
        print("updated member_json: \n", member_json)
        dskresp = bb.GetDataSources(params={'fields':'id, externalId'}, sync=True)
        dsks_json = dskresp.json()
        print ("DSKS:\n", dsks_json["results"])
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks)
        print ("SIZE OF DSK LIST:", len(dsks))
                
        context = {
            'member_json': member_json,
            'dsks_json': dsks,
        }
    else:
        error_json = membership_result.json()
        print (f"RESPONSE:\n", error_json)
        data = {
            'is_found': False,
            'error_json': error_json,
        }

        return JsonResponse(data)

    data = {
        'is_found': True,
        'memberships_json': member_json,
        'dsks_json': dsks,
    }

    return JsonResponse(data)
# [DONE] Retrieve a list of course memberships
def getCourseMemberships(request):
    print("getCourseMembers Called...")
    print("request method: ", request.method)

    searchBy = request.GET.get('searchBy') #externalId || userName
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print("LEARNFQDN", LEARNFQDN)
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)

    if (searchBy == 'externalId'):
        crs = "externalId:" + searchValue
    else:
        crs = "courseId:" + searchValue

    bb_json = request.session.get('bb_json')

    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    memberships_result = bb.GetCourseMemberships( courseId = crs, limit = 1500, params = {'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, childCourseId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True )

    print("memberships_result status: ", memberships_result.status_code)
    membershipsResultJSON = memberships_result.json()
    print(f"\nmemberships_result:\n", membershipsResultJSON)

    if (memberships_result.status_code == 200):
        dsksResp = bb.GetDataSources(params = {'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        #print("DSKS_JSON: \n", dsks_json)
        dsks = dsks_json["results"]
        #print("DSKS: \n", dsks)
        dsks = sortDsk(dsks)
        #print("SORTEDDSKS: \n", dsks)
        
        for idx, membership in enumerate(membershipsResultJSON["results"]):
            print("\nMEMBERSHIP: ", membership["dataSourceId"])
            for dsk in dsks:
                #print("DSK:\n", dsk)
                #print("DSKID: ", dsk["id"])
                if (dsk["id"] == membership["dataSourceId"]):
                    print("DSKEXTERNALID: ", dsk["externalId"])
                    membershipsResultJSON["results"][idx]["dataSourceId"] = dsk["externalId"]
                    print(membershipsResultJSON["results"][idx]["dataSourceId"])
        
        print(f"\nmemberships_result AFTER:\n", membershipsResultJSON)

    #Use asynchronous when processing requests
    # tasks = []
    # for user in users:
    #     tasks.append(bb.GetUser(user), sync=False)
    #     resps = await asynchio.gather(*tasks)


    context = {
        'is_found': True,
        'memberships_json': membershipsResultJSON,
        'dsks_json': dsks,
    }

    return JsonResponse(context)
#[DONE] Update a single course membership
def updateCourseMembership(request):
    finalResponse = {}
    isFoundStatus = False

    print("\ngetCourseMember Called...")
    print("request method: ", request.method)

    #{"searchByCrs":"externalId","searchValueCrs":"moneil-available","searchValueUsr":"moneil","searchByUsr":"externalId"}
    crsSearchBy = request.GET.get('crsSearchBy') #externalId || userName
    crsToSearchFor = request.GET.get('crsToSearchFor')
    usrSearchBy = request.GET.get('usrSearchBy') #externalId || userName
    usrToSearchFor = request.GET.get('usrToSearchFor')
    userArray =  request.GET.getlist('pmcUserId[]')
    print("getCourseMembership::crsSearchBy", crsSearchBy)
    print ("getCourseMembership::crsToSearch: ", crsToSearchFor)
    print ("getCourseMembership::usrSearchBy: ", usrSearchBy)
    print ("getCourseMembership::usrToSearchFor", usrToSearchFor)
    print("request pmcUsersList: \n", userArray)

    if (crsSearchBy == 'externalId'):
        crs = "externalId:" + crsToSearchFor
    else:
        crs = "courseId:" + crsToSearchFor
    if (usrSearchBy == 'externalId'):
        usr = "externalId:" + usrToSearchFor
    else:
        usr = "userName:" + usrToSearchFor

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        return HttpResponseRedirect(reverse('get_auth_code'))
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    dsks_json = bb.GetDataSources(params = {'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    resps = {'results':[]}
    print("RESPS SET TO EMPTY RESULTS")

    # if (request.GET.get('isUpdateRequired1') == 'true'):
    print("isUpdateRequired1", request.GET.get('isUpdateRequired1'))
    payload={}
    if (request.GET.get('isAvailabilityUpdateRequired1')):
        print("isAvailabilityUpdateRequired1: ", request.GET.get('isAvailabilityUpdateRequired1'))

        if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
            payload={'availability':{"available":request.GET.get('selectedAvailability')}}
            print("availability: ",request.GET.get('selectedAvailability'))

    if (request.GET.get('isDataSourceKeyUpdateRequired1')):
        print("isDataSourceKeyUpdateRequired1: ", request.GET.get('isDataSourceKeyUpdateRequired1'))
            
        if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
            payload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
            print("dataSourceId: ",request.GET.get('selectedDataSourceKey'))
            
            print("PAYLOAD: \n", payload)

    resp = bb.UpdateMembership(courseId=crs, userId = usr, payload=payload, params = {'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True )

    respJSON = resp.json()

    if (resp.status_code == 200):
        print("RESP:\n", resp.json())
        #resps["results"].append(respJSON["results"])
        print("RESPJSON:\n", respJSON)
        print("RESPJSON:dataSourceId", respJSON["dataSourceId"])
        isFoundStatus = True

        for dsk in dsks:
            #print("DSK:\n", dsk)
            #print("DSKID: ", dsk["id"])
            if (dsk["id"] == respJSON["dataSourceId"]):
                print("DSKEXTERNALID: ", dsk["externalId"])
                respJSON["dataSourceId"] = dsk["externalId"]
                print("RESPJSON:dataSourceId", respJSON["dataSourceId"])
            # else:
            #     error_json["results":] = resp.json()
            #     print("resp.status_code:", resp.status_code)
            #     print (f"RESPONSE:\n", error_json)

        resps["results"].append(respJSON)
        print("RESPS:\n", resps)
        
        finalResponse = {
            "is_found": isFoundStatus,
            "updateList": resps["results"],
        }

        print("FINAL RESPONSE:\n", finalResponse)
                   
    return JsonResponse(finalResponse)
#[DONE] Update a list of course memberships
def updateCourseMemberships(request):
    finalResponse = {}
    print("request method: ", request.method)
    print("request: ", request)

    if (request.GET.get("crsorusr") == 'byCrsUsr'):
        searchValue = request.GET.get("crsSearchValue")
        print("request searchValue: ", searchValue)
        searchBy = request.GET.get("crsSearchBy")
        print("request searchBy: ", searchBy)
    elif (request.GET.get("crsorusr") == 'byCrs'):
        searchValue = request.GET.get("crsToSearchFor")
        print("request searchValue: ", searchValue)
        searchBy = request.GET.get("crsSearchBy")
        print("request searchBy: ", searchBy)
    elif (request.GET.get("crsorusr") == 'byUsr'):
        searchValue = request.GET.get("crsToSearchFor")
        print("request searchValue: ", searchValue)
        searchBy = request.GET.get("crsSearchBy")
        print("request searchBy: ", searchBy)

    userArray =  request.GET.getlist('pmcUserId[]')
    print("request pmcUsersList: \n", userArray)
    

    if (searchBy == "externalId"):
        crs = "externalId:"+searchValue
        print ("COURSE TO UPDATE: ", crs)
    elif (searchBy == "courseId"):
        crs = "courseId:"+searchValue
        print ("COURSE TO UPDATE:", crs)

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        return HttpResponseRedirect(reverse('get_auth_code'))
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    dsks_json = bb.GetDataSources(params = {'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    resps = {'results':[]}
    print("RESPS SET TO EMPTY RESULTS")
    isFoundStatus = False

    if (request.GET.get('isUpdateRequired1') == 'true'):
        print("isUpdateRequired1", request.GET.get('isUpdateRequired1'))

        for user in userArray:            
            payload={}
            if (request.GET.get('isAvailabilityUpdateRequired1')):
                print(user + ": isAvailabilityUpdateRequired1: ", request.GET.get('isAvailabilityUpdateRequired1'))

                if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                    payload={'availability':{"available":request.GET.get('selectedAvailability')}}
                    print(user + ": availability: ",request.GET.get('selectedAvailability'))

            if (request.GET.get('isDataSourceKeyUpdateRequired1')):
                print(user + ": isDataSourceKeyUpdateRequired1: ", request.GET.get('isDataSourceKeyUpdateRequired1'))
            
                if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                    payload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
                    print(user + ": dataSourceId: ",request.GET.get('selectedDataSourceKey'))
            
            print("PAYLOAD: \n", payload)

            resp = bb.UpdateMembership(courseId=crs, userId = user, payload=payload, params = {'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True )

            respJSON = resp.json()

            if (resp.status_code == 200):
                print("RESP:\n", resp.json())
                #resps["results"].append(respJSON["results"])
                print ("User:" + user + "UPDATED WITH PAYLOAD: \n", payload)
                print("RESPJSON:\n", respJSON)
                print("RESPJSON:dataSourceId", respJSON["dataSourceId"])
                isFoundStatus = True

                for dsk in dsks:
                    #print("DSK:\n", dsk)
                    #print("DSKID: ", dsk["id"])
                    if (dsk["id"] == respJSON["dataSourceId"]):
                        print("DSKEXTERNALID: ", dsk["externalId"])
                        respJSON["dataSourceId"] = dsk["externalId"]
                        print("RESPJSON:dataSourceId", respJSON["dataSourceId"])
                resps["results"].append(respJSON)

            elif (resp.status_code == 409):
                print("resp.status_code:", resp.status_code)
                print ("CHILD COURSE MEMBERSHIP: Get Child Course...")
                print("crsToSearchFor: ", searchValue)
                cqmembership_result = bb.GetMembership( courseId = searchValue, userId = user, params = {'fields': 'id, courseId, userId, childCourseId'}, sync=True )

                cqmembership_resultJSON = cqmembership_result.json()
                print("CHILD QUEST:JSON", cqmembership_resultJSON)
                print("CHILD QUEST:CHILDCOURSEID", cqmembership_resultJSON["childCourseId"])

                

                resp2 = bb.UpdateMembership(courseId=cqmembership_resultJSON["childCourseId"], userId = user, payload=payload, params = {'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True )
                print("RESP2:\n", resp2.json())

            print("RESPS:\n", resps)
        
        print("ISFOUNDSTATUS: ", isFoundStatus)
        finalResponse = {
            "is_found": isFoundStatus,
            "pmcUserId[]": userArray,
            "updateList": resps["results"],
        }

        print("FINAL RESPONSE:\n", finalResponse)
                   
    return JsonResponse(finalResponse)
#[DONE] Retrieve a list of user memberships
def getUserMemberships(request):
    print("getUserMemberships Called...")
    print("request method: ", request.method)

    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print("LEARNFQDN", LEARNFQDN)
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)

    if (searchBy == 'externalId'):
        usr = "externalId:" + searchValue
    else:
        usr = "userName:" + searchValue

    bb_json = request.session.get('bb_json')

    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    memberships_result = bb.GetUserMemberships( userId = usr, limit = 1500, params = {'expand': 'course', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, course.name, childCourseId, course.externalId'}, sync=True )

    print("memberships_result status: ", memberships_result.status_code)
    membershipsResultJSON = memberships_result.json()
    print(f"\nmemberships_result:\n", membershipsResultJSON)

    if (memberships_result.status_code == 200):
        dsksResp = bb.GetDataSources(params = {'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        #print("DSKS_JSON: \n", dsks_json)
        dsks = dsks_json["results"]
        #print("DSKS: \n", dsks)
        dsks = sortDsk(dsks)
        #print("SORTEDDSKS: \n", dsks)
        
        for idx, membership in enumerate(membershipsResultJSON["results"]):
            print("\nMEMBERSHIP: ", membership["dataSourceId"])
            for dsk in dsks:
                #print("DSK:\n", dsk)
                #print("DSKID: ", dsk["id"])
                if (dsk["id"] == membership["dataSourceId"]):
                    print("DSKEXTERNALID: ", dsk["externalId"])
                    membershipsResultJSON["results"][idx]["dataSourceId"] = dsk["externalId"]
                    print(membershipsResultJSON["results"][idx]["dataSourceId"])
        
        print(f"\nmemberships_result AFTER:\n", membershipsResultJSON)

    #Use asynchronous when processing requests
    # tasks = []
    # for user in users:
    #     tasks.append(bb.GetUser(user), sync=False)
    #     resps = await asynchio.gather(*tasks)


    context = {
        'is_found': True,
        'memberships_json': membershipsResultJSON,
        'dsks_json': dsks,
    }

    return JsonResponse(context)
#[DONE] Update a list of user memberships
def updateUserMemberships(request):
    # {"crsSearchBy":"not_required","crsToSearchFor":"not_required","usrToSearchFor":"moneil","usrSearchBy":"externalId","isUpdateRequired1":"true","isAvailabilityUpdateRequired1":"true","selectedAvailability":"Yes","isDataSourceKeyUpdateRequired1":"true","selectedDataSourceKey":"_7_1","pmcUserId[]":["_9682_1:_1354_1","_9681_1:_1354_1"],"crsorusr":"byUsr"}
    finalResponse = {}
    print("request method: ", request.method)
    print("request: ", request)

    crsArray =  request.GET.getlist('pmcUserId[]')
    print("REQUEST pmcUsersList: \n", crsArray)

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        return HttpResponseRedirect(reverse('get_auth_code'))
    else:
        print('got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            print('expired token')
            request.session['bb_json'] = None
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        print(f'expiration: {bb.expiration()}')

    dsks_json = bb.GetDataSources(params = {'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    resps = {'results':[]}
    print("RESPS SET TO EMPTY RESULTS")
    isFoundStatus = False

    if (request.GET.get('isUpdateRequired1') == 'true'):
        print("isUpdateRequired1", request.GET.get('isUpdateRequired1'))

        for crs in crsArray:            
            payload={}
            #print("COURSE RECORD: ", crs)
            passedCrsId, passedUsrId = crs.split(':', 1)
            #print("COURSE ID: ", passedCrsId)
            #print("USER ID: ", passedUsrId)
            if (request.GET.get('isAvailabilityUpdateRequired1')):
                print("isAvailabilityUpdateRequired1: ", request.GET.get('isAvailabilityUpdateRequired1'))

                if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                    payload={'availability':{"available":request.GET.get('selectedAvailability')}}
                    print("availability: ",request.GET.get('selectedAvailability'))

            if (request.GET.get('isDataSourceKeyUpdateRequired1')):
                print("isDataSourceKeyUpdateRequired1: ", request.GET.get('isDataSourceKeyUpdateRequired1'))
            
                if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                    payload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
                    print("dataSourceId: ",request.GET.get('selectedDataSourceKey'))
            
            print("PAYLOAD: \n", payload)

            resp = bb.UpdateMembership(courseId=passedCrsId, userId=passedUsrId, payload=payload, params = {'expand': 'course', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, course.name, course.externalId'}, sync=True )

            respJSON = resp.json()

            if (resp.status_code == 200):
                #print("RESP:\n", resp.json())
                #resps["results"].append(respJSON["results"])
                print ("UPDATED MEMBERSHIP WITH PAYLOAD: \n", payload)
                #print("RESPJSON:\n", respJSON)
                #print("RESPJSON:dataSourceId", respJSON["dataSourceId"])
                isFoundStatus = True

                for dsk in dsks:
                    #print("DSK:\n", dsk)
                    #print("DSKID: ", dsk["id"])
                    if (dsk["id"] == respJSON["dataSourceId"]):
                        #print("DSKEXTERNALID: ", dsk["externalId"])
                        respJSON["dataSourceId"] = dsk["externalId"]
                        #print("RESPJSON:dataSourceId", respJSON["dataSourceId"])

                    # add course name...
                    crsResp = bb.GetCourse(courseId=passedCrsId, params = {'fields': 'name, externalId'})
                    
                    if (resp.status_code == 200):
                        #print("CRSRESP:\n", crsResp.json())
                        respJSON["course"] = crsResp.json()
                        #print("RESPRESP:\n", respJSON)
            else:
                error_json["results":] = resp.json()
                print("resp.status_code:", resp.status_code)
                print (f"RESPONSE:\n", error_json)

            resps["results"].append(respJSON)
            #print("RESPS:\n", resps)
        
        print("ISFOUNDSTATUS: ", isFoundStatus)
        finalResponse = {
            "is_found": isFoundStatus,
            "updateList": resps["results"],
        }

        print("FINAL RESPONSE:\n", finalResponse)
                   
    return JsonResponse(finalResponse)
#[DONE] Retrieve User data
def getUser(request):
    # returns a list of one user - saves on javascript side.
    searchBy = request.GET.get('searchBy')
    searchValueUsr = request.GET.get('searchValueUsr')
    if (searchValueUsr is not None):
        searchValueUsr = searchValueUsr.strip()
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUEUSR: ", searchValueUsr)

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        request.session['target_view'] = 'users'
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

    if ISGUESTUSER:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )
     
    #Process request...
    if (searchBy == 'externalId'):
        usr="externalId:" + searchValueUsr
    elif (searchBy == 'userName'):
        usr="userName:" + searchValueUsr
    
    print(f"user pattern: {usr}")
    
    resp = bb.GetUser(userId = usr, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True )
    if (resp.status_code == 200):
        user_json = resp.json() 
        dskresp = bb.GetDataSource(dataSourceId = user_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        user_json['dataSourceId'] = dsk_json['externalId']
        user_json['searchValueUsr'] = searchValueUsr
        user_json['searchBy'] = searchBy
        dskresp = bb.GetDataSources(params={'fields':'id, externalId'}, sync=True)
        dsks_json = dskresp.json()
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks)

        context = {
          'user_json': user_json,
          'dsks_json': dsks,
        }

    else:
        error_json = resp.json()
        print (f"RESPONSE:\n", error_json)
        context = {
            'error_json': error_json,
        }

    return JsonResponse(context)
#[DONE] Update User data
def updateUser(request):
    print("UPDATE USER...")
    print ('Request:\n ')
    print (request)
    print("isUpdateRequired1: ", request.GET.get("isUpdateRequired1"))
    print("isAvailabilityUpdateRequired1:", request.GET.get("isAvailabilityUpdateRequired1"))
    print("selectedAvailability: ", request.GET.get("selectedAvailability"))
    print("isDataSourceKeyUpdateRequired1: ", request.GET.get("isDataSourceKeyUpdateRequired1"))
    selectedDSK = request.GET.get("selectedDataSourceKey")
    print("selectedDataSourceKey: ", selectedDSK)
    updateValue = request.GET.get('pmcUserId[]')
    print("UPDATE VALUE: ", updateValue)

    isFoundStatus = False
    passedPayload={}

    if (request.GET.get('isAvailabilityUpdateRequired1')):
        if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
            print("AVAILABILITY UPDATE REQUIRED")
            passedPayload={'availability':{"available":request.GET.get('selectedAvailability')}}
    if (request.GET.get('isDataSourceKeyUpdateRequired1')):
        if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
            passedPayload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
            print("DATASOURCE UPDATE REQUIRED")
            
    print ("PASSABLE PAYLOAD:\n", passedPayload)

    # for x, y in passedPayload.items():
    #     print(x, y)

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        request.session['target_view'] = 'users'
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
        print(f'bbrest expiration: {bb.expiration()}')

    resp = bb.UpdateUser(userId = updateValue, payload=passedPayload, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True )

    if (resp.status_code == 200):
        result_json = resp.json() #return actual error
        dskresp = bb.GetDataSource(dataSourceId = result_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        print (f"RESPONSE:\n", result_json)
        isFoundStatus = True

        result_json['dataSourceId'] = dsk_json['externalId']

        context = {
          "is_found": isFoundStatus,
          'result_json': result_json,
        }
    else:
        error_json = resp.json()
        print (f"RESPONSE:\n", error_json)
        context = {
            "is_found": isFoundStatus,
            'error_json': error_json,
        }

    return JsonResponse(context)
#[DONE] Retrieve a single course data
def getCourse(request):
    # returns a list of one course - saves on javascript side.

    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        request.session['target_view'] = 'users'
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

    if ISGUESTUSER:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )
     
    #Process request...
    if (searchBy == 'externalId'):
        crs="externalId:" + searchValue
    elif (searchBy == 'userName'):
        crs="userName:" + searchValue
    else:
        crs = searchValue
    
    print(f"course pattern: {crs}")

    isFoundStatus = False

    resp = bb.GetCourse(courseId = crs, params = {'fields':'id, courseId, externalId, name, organization, availability.available, dataSourceId, modified'}, sync=True )

    print("GETCOURSE RESP: \n", resp.json())

    if (resp.status_code == 200):
        course_json = resp.json() 

        dskresp = bb.GetDataSource(dataSourceId = course_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        course_json['dataSourceId'] = dsk_json['externalId']
        course_json['searchValue'] = searchValue
        course_json['searchBy'] = searchBy
        dskresp = bb.GetDataSources(params={'fields':'id, externalId'}, sync=True)
        dsks_json = dskresp.json()
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks)
        
        isFoundStatus = True

        context = {
            'is_found': isFoundStatus,
            'course_json': course_json,
            'dsks_json': dsks,
        }

    else:
        error_json = resp.json()
        print (f"RESPONSE:\n", error_json)
        context = {
            'error_json': error_json,
        }

    return JsonResponse(context)


#[] Update a single course
def updateCourse(request):
    print("UPDATE COURSE...")
    print ('Request:\n ')
    print (request)
    print("isUpdateRequired1: ", request.GET.get("isUpdateRequired1"))
    print("isAvailabilityUpdateRequired1:", request.GET.get("isAvailabilityUpdateRequired1"))
    print("selectedAvailability: ", request.GET.get("selectedAvailability"))
    print("isDataSourceKeyUpdateRequired1: ", request.GET.get("isDataSourceKeyUpdateRequired1"))
    selectedDSK = request.GET.get("selectedDataSourceKey")
    print("selectedDataSourceKey: ", selectedDSK)
    updateValue = request.GET.get('pmcId[]')
    print("UPDATE VALUE: ", updateValue)

    isFoundStatus = False
    passedPayload={}

    if (request.GET.get('isAvailabilityUpdateRequired1')):
        if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
            print("AVAILABILITY UPDATE REQUIRED")
            passedPayload={'availability':{"available":request.GET.get('selectedAvailability')}}
    if (request.GET.get('isDataSourceKeyUpdateRequired1')):
        if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
            passedPayload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
            print("DATASOURCE UPDATE REQUIRED")
            
    print ("PASSABLE PAYLOAD:\n", passedPayload)

    # for x, y in passedPayload.items():
    #     print(x, y)

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        print('pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        request.session['target_view'] = 'users'
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
        print(f'bbrest expiration: {bb.expiration()}')

    resp = bb.UpdateCourse(courseId = updateValue, payload=passedPayload, params = {'fields':'id, courseId, externalId, name, organization, availability.available, dataSourceId, modified'}, sync=True )

    if (resp.status_code == 200):
        result_json = resp.json() #return actual error
        dskresp = bb.GetDataSource(dataSourceId = result_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        print (f"RESPONSE:\n", result_json)
        isFoundStatus = True

        result_json['dataSourceId'] = dsk_json['externalId']

        context = {
          "is_found": isFoundStatus,
          'result_json': result_json,
        }
    else:
        error_json = resp.json()
        print (f"RESPONSE:\n", error_json)
        context = {
            "is_found": isFoundStatus,
            'error_json': error_json,
        }

    return JsonResponse(context)
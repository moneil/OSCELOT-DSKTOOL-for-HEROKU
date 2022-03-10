from django.http import HttpResponse, HttpResponseRedirect, HttpRequest
from django.shortcuts import render
from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.cache import never_cache
import bbrest
from bbrest import BbRest
import jsonpickle
import json
import os
import uuid
import time
import logging

from django.http import JsonResponse
#from django.views.generic import View
#from django.views.decorators.csrf import csrf_exempt
#from django.utils.decorators import method_decorator
#from django.forms.models import model_to_dict
#from django.shortcuts import render

# # THIS VERSIONS SORT OF WORKS (02/28/2021)
# # does on load checks but when user token expires does not reset token.

# Globals
# bb: BbRest object - required for all BbRest requests
# bb_json: BbRest session details
# ISGUESTUSER: 3LO'd as a guest user

global bb
global bb_json
global ISGUESTUSER
global ISVALIDROLE

bb = None
bb_json = None
ISVALIDROLE = False
ISGUESTUSER = True
bb_refreshToken = None

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.DEBUG,
    datefmt='%Y-%m-%d %H:%M:%S')

# HTTP Error handling:
class makeRequestHTTPError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
    def __str__(self):
        return repr(self.code + ": " + self.message)

# bbrestSetup()
# identifies whether bbrest and tokens are setup for processing the request.
def BbRestSetup(request, targetView=None, redirectRequired=False):
    global bb
    global bb_json
    global ISGUESTUSER
    
    ISGUESTUSER = False

    logging.debug('BBRESTSETUP: ENTER')
    logging.debug(f'BBRESTSETUP INPUTS: targetView: {targetView}')
    logging.debug(f'BBRESTSETUP INPUTS: redirectRequired: {redirectRequired}')
    
    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        logging.debug('BBRESTSETUP: Pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        request.session['target_view'] = targetView 
        logging.debug(f"BBRESTSETUP request.session['target_view']: {request.session['target_view']}")
        return HttpResponseRedirect(reverse('get_auth_code'))
    else:
        logging.debug('BBRESTSETUP: got BbRest from session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            logging.debug('BBRESTSETUP:expired token')
            
            request.session['bb_json'] = None
            # if targetView == 'whoami':
            #     logging.debug('BBRESTSETUP: Expired call whoami')
            #     whoami(request)
            # elif targetView == 'index':
            #     logging.debug('BBRESTSETUP: Expired call index')
            #     index(request)
            # else:
            #     logging.debug('BBRESTSETUP: Expired call but NOT index or whoami - just validate?')
            BbRestSetup(request, targetView)

        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
        logging.info(f'BBRESTSETUP: Token expiration: {bb.expiration()}')


    # if ISGUESTUSER:
    #     context = {
    #         'learn_server': LEARNFQDN,
    #     }   
    #     return render(request, 'guestusernotallowed.html', context=context)
    
    logging.info('BBRESTSETUP: EXIT')
# end BbRestSetup

def isValidRole(bb_json):
    global ISVALIDROLE

    ISVALIDROLE=False

    validRoles=['SystemAdmin']
    validRole=False

    bb = jsonpickle.decode(bb_json)
    resp = bb.call('GetUser', userId = "me", params = {'fields':'userName, systemRoleIds'}, sync=True ) 
    
    user_json = resp.json()

    userSystemRoles = user_json['systemRoleIds']
    logging.debug("userSystemRoles: " + json.dumps(userSystemRoles))
    for role in userSystemRoles:
        if role in validRoles:
            logging.debug("ValidRole: " + role)
            validRole=True

    ISVALIDROLE=validRole
    logging.debug("ISVALIDROLE: " + str(ISVALIDROLE))

    return validRole


# [DONE]
def isGuestUser(bb_json):
    global ISGUESTUSER

    guestStatus = False

    bb = jsonpickle.decode(bb_json)
    resp = bb.call('GetUser', userId = "me", params = {'fields':'userName'}, sync=True ) 
    
    user_json = resp.json()

    logging.debug(f"ISGUESTUSER::userName: {user_json['userName']}")

    if user_json['userName'] == 'guest':
        guestStatus = True
        ISGUESTUSER = True
    else:
        guestStatus = False
        ISGUESTUSER = False

    logging.debug("ISGUESTUSER: " + str(ISGUESTUSER))
    return guestStatus


# Pull configuration... use env settings if no local config file
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

# print("VIEWS: KEY: ", KEY)
# print("VIEWS: SECRET: ", SECRET)
# print("VIEWS: LEARNFQDN: ", LEARNFQDN)

# [DONE] Authorizes user after AuthN if necessary
@never_cache
@never_cache
def index(request):
    # global bb
    # global bb_json

    # bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    # logging.info("INDEX: bb expiration: " + bb.expiration())
    # resp = bb.GetVersion()
    # access_token = bb.token_info['access_token']
    # version_json = resp.json()

    # BbRestSetup(request, targetView='index')
    bb_json = request.session.get('bb_json')

    if (bb_json is None):
        logging.info('INDEX: BbRest not found in session')
        # request.session.flush()
        try:
            bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
            bb_json = jsonpickle.encode(bb)
        except:
            logging.critical('INDEX: Could not set BbREST in Session, Check Configuration KEY and SECRET.')
        request.session['bb_json'] = bb_json
        logging.info('INDEX: Pickled BbRest added to session')
        request.session['target_view'] = 'index' 
        return HttpResponseRedirect(reverse('get_auth_code'))
    else:
        logging.info('INDEX: Found BbRest in session')
        bb = jsonpickle.decode(bb_json)
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        logging.info("INDEX: bb token expired?: " + str(bb.is_expired()))
        logging.debug("BB_JSON: Token Info: refresh_token " + str(bb.token_info.get('refresh_token')))
        logging.debug("BB_JSON: Token Info: " + str(bb.token_info))


    
    resp = bb.GetVersion()
    access_token = bb.token_info['access_token']
    version_json = resp.json()
        
        
        # if bb.is_expired():
        # # is_expired = True
        # # if is_expired:
        #     logging.info('INDEX: Expired Token - clear cookie and bb_json, then request new token.')
        #     request.session.flush()
        #     request.session['bb_json'] = None
        #     index(request)
        # bb.supported_functions() # This and the following are required after
        # bb.method_generator()    # unpickling the pickled object.
    

    # resp = bb.GetVersion()
    # access_token = bb.token_info['access_token']
    # version_json = resp.json()

    context = {
        'learn_server': LEARNFQDN,
        'version_json' : version_json,
        'access_token' : access_token,
    }

    return render(request, 'index.html', context=context)

# [DONE] WHOAMI returns the current user info/status
@never_cache
def whoami(request):
    global bb
    global bb_json

    # View function for whoami page of site.

    # BbRestSetup(request, 'whoami')

    bb_json = request.session.get('bb_json')
    if (bb_json is None):
        bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
        bb_json = jsonpickle.encode(bb)
        logging.info('WHOAMI: Pickled BbRest putting it on session')
        request.session['bb_json'] = bb_json
        request.session['target_view'] = 'whoami' 
        return HttpResponseRedirect(reverse('get_auth_code'))
        # for some reason i do not get a new auth toke/code here
    else:
        logging.info('WHOAMI: Found BbRest in session')
        bb = jsonpickle.decode(bb_json)
        if bb.is_expired():
            logging.info('WHOAMI: Expired Token - clear cookie and bb_json, then request new token.')
            # request.session['bb_json'] = None
            whoami(request)
        bb.supported_functions() # This and the following are required after
        bb.method_generator()    # unpickling the pickled object.
    
    resp = bb.call('GetUser', userId = "me", params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, dataSourceId, created'}, sync=True )

    user_json = resp.json()

    logging.info("WHOAMI: user_json: " + json.dumps(user_json))

    try:
        logging.info("WHOAMI: try to get user information.")
        logging.debug("WHOAMI: user_json['dataSourceId']: " + user_json['dataSourceId'])
        logging.info("WHOAMI: GetDataSource")
        # dskresp = bb.call('GetDataSource', dataSourceId = user_json['dataSourceId'], sync=True)
        dskresp = bb.GetDataSource(dataSourceId=user_json['dataSourceId'], sync=True)
        logging.debug("WHOAMI: POST WHOAMI DATASOURCE REQUEST.")
        dsk_json = dskresp.json()
        logging.debug("WHOAMI: dsk_json: " + json.dumps(dsk_json))
        user_json['dataSourceId'] = dsk_json['externalId']

        logging.info("WHOAMI: user_json: dataSourceId: " + user_json['dataSourceId'])
    except:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )

    context = {
        'user_json': user_json,
        'access_token': bb.token_info['access_token']
    }

    logging.info(f'WHOAMI: Token expiration: {bb.expiration()}')

    # Render the HTML template index.html with the data in the context variable
    return render(request, 'whoami.html', context=context)

# [DONE] (TASK BASED)
def courses(request):
    global ISVALIDROLE

    task = request.GET.get('task')
    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    # logging.debug("COURSES: SEARCHBY: ", searchBy)

    # logging.debug("COURSES: SEARCHVALUE: ", searchValue)
    # logging.debug("COURSES: TASK: ", task)

    if ISVALIDROLE:
        logging.debug("User has valid role")
        BbRestSetup(request, targetView='courses', redirectRequired=True)
    else:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'notauthorized.html', context=context )

    if (task == 'search'):
        #Process request...
        print (f"COURSE REQUEST: ACTION {task}")
        searchValue = request.GET.get('searchValue')
        if (searchValue is not None):
            searchValue = searchValue.strip()
        
        logging.debug(f"COURSE REQUEST: CRS: {searchValue}")
        logging.debug(f"Process by {searchBy}")
        if (searchBy == 'externalId'):
            crs="externalId:" + searchValue
            logging.debug(f"course pattern: {crs}")
        elif (searchBy == 'primaryId'):
            crs=searchValue
            logging.debug(f"course pattern: {crs}")
        elif (searchBy == 'courseId'):
            crs="courseId:" + searchValue
            logging.debug(f"course pattern: {crs}")
        resp = bb.GetCourse(courseId = crs, params = {'fields':'id, courseId, externalId, name, availability.available, dataSourceId, created'}, sync=True )
        if (resp.status_code == 200):
            course_json = resp.json() 
            dskresp = bb.GetDataSource(dataSourceId = course_json['dataSourceId'], sync=True)
            dsk_json = dskresp.json()
            course_json['dataSourceId'] = dsk_json['externalId']
            course_json['searchValue'] = searchValue
            course_json['searchBy'] = searchBy
            dskresp = bb.GetDataSources(limit = 5000, params={'fields':'id, externalId'}, sync=True)
            dsks_json = dskresp.json()
            logging.debug("DSKS:\n", dsks_json["results"])
            dsks = dsks_json["results"]
            dsks = sortDsk(dsks, 'externalId')
            logging.debug("SIZE OF DSK LIST:", len(dsks))
                
            context = {
              'course_json': course_json,
              'dsks_json': dsks,
            }
        else:
            error_json = resp.json()
            logging.debug(f"RESPONSE:\n", error_json)
            context = {
                'error_json': error_json,
            }

        return render(request, 'courses.html', context=context)

    if (task == 'process'):
        logging.debug(f"COURSE REQUEST: ACTION {task}")
        logging.debug(f"Process by {searchBy}")
        logging.debug('Request:\n ')
        logging.debug(request)
        payload={}
        if (request.GET.get('isAvailabilityUpdateRequired1')):
            if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
                payload={'availability':{"available":request.GET.get('selectedAvailability')}}
        if (request.GET.get('isDataSourceKeyUpdateRequired1')):
            if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
                payload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
            
        logging.debug("PAYLOAD\n")
        for x, y in payload.items():
            logging.debug(x, y)

        # Build and make bb request...
        if (searchBy == 'externalId'):
            crs="externalId:" + searchValue
        elif (searchBy == 'primaryId'):
            crs=searchValue
            logging.debug(f"course pattern: {crs}")
        elif (searchBy == 'courseId'):
            crs="courseId:" + searchValue
            logging.debug(f"course pattern: {crs}")

        logging.debug(f"course pattern: {crs}")

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
            logging.debug(f"RESPONSE:\n", error_json)
            context = {
                'error_json': error_json,
            }

        return render(request, 'courses.html', context=context)

    return render(request, 'courses.html')

# [DONE] (TASK BASED)
def enrollments(request):
    global ISVALIDROLE

    task = request.GET.get('task')
    searchBy = request.GET.get('searchBy')

    # BbRestSetup(request, targetView='enrollments', redirectRequired=True)
    
    if ISVALIDROLE:
        logging.debug("User has valid role")
        BbRestSetup(request, targetView='enrollments', redirectRequired=True)
    else:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'notauthorized.html', context=context )

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
                dskresp = bb.GetDataSources(limit = 5000, params={'fields':'id, externalId'}, sync=True)
                dsks_json = dskresp.json()
                print ("DSKS:\n", dsks_json["results"])
                dsks = dsks_json["results"]
                dsks = sortDsk(dsks, 'externalId')
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

# [DONE] (TASK BASED)
def users(request):
    global bb_json
    global ISVALIDROLE

    task = request.GET.get('task')
    searchBy = request.GET.get('searchBy')
    searchValueUsr = request.GET.get('searchValueUsr')
    if (searchValueUsr is not None):
        searchValueUsr = searchValueUsr.strip()
    print ("users: SEARCHBY: ", searchBy)
    print ("users: SEARCHVALUEUSR: ", searchValueUsr)
    print ("users: TASK: ", task)

    # View function for users page of site.
    if ISVALIDROLE:
        logging.debug("User has valid role")
        BbRestSetup(request, targetView='users', redirectRequired=True)
        return render(request, 'users.html')
    else:
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'notauthorized.html', context=context )


# [DONE]
def get_access_token(request):
    global bb_json
    global bb
    
    # Happens when the user hits index the first time and hasn't authenticated on Learn
    # Part II. Get an access token for the user that logged in. Put that on their session.
    bb_json = request.session.get('bb_json')
    target_view = request.session.get('target_view')
    logging.info('GET_ACCESS_TOKEN: got BbRest from session')
    bb = jsonpickle.decode(bb_json)
    bb.supported_functions() # This and the following are required after
    bb.method_generator()    # unpickling the pickled object.
    # Next, get the code parameter value from the request
    redirect_uri = reverse(get_access_token)
    absolute_redirect_uri = f"https://{request.get_host()}{redirect_uri}"

    state = request.GET.get('state', default= "NOSTATE")
    logging.info(f'GET_ACCESS_TOKEN: GOT BACK state: {state}')
    stored_state = request.session.get('state')
    logging.info(f'GET_ACCESS_TOKEN: STORED STATE: {stored_state}')
    if (stored_state != state):
        return HttpResponseRedirect(reverse('notauthorized'))

    code =  request.GET.get('code', default = None)
    if (code == None):
        exit()

    user_bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}", code=code, redirect_uri=absolute_redirect_uri )    
    bb_json = jsonpickle.encode(user_bb)

    if (isGuestUser(bb_json)):
        context = {
            'learn_server': LEARNFQDN,
        }   
        return render(request, 'guestusernotallowed.html', context=context )

    if (not isValidRole(bb_json)):
        # return notauthorized page
        return render(request, 'notauthorized.html', context=context )

    logging.info('GET_ACCESS_TOKEN: pickled BbRest and putting it on session')
    request.session['bb_json'] = bb_json
    return HttpResponseRedirect(reverse(f'{target_view}'))

# [DONE]
def get_auth_code(request):
    global bb_json
    global bb
    
    # Happens when the user hits index the first time and hasn't authenticated on Learn
    # Part I. Request an authorization code oauth2/authorizationcode
    logging.info(f"GET_AUTH_CODE: REQUEST URI:{request.build_absolute_uri()}")
    try: 
        bb_json = request.session.get('bb_json')
        logging.info('GET_AUTH_CODE: got BbRest from session')
        bb = jsonpickle.decode(bb_json)
    except:
        #sideways session go to index page and force get_access_token
        logging.info(f"GET_AUTH_CODE: Something went sideways with bb session, reverse to target e.g. 'index', maybe you should have thrown an error here.")
        return HttpResponseRedirect(reverse('index'))

    bb.supported_functions() # This and the following are required after
    bb.method_generator()    # unpickling the pickled object. 
    # The following gives the path to the resource on the server where we are running, 
    # but not the protocol or host FQDN. We need to prepend those to get an absolute redirect uri.
    redirect_uri = reverse(get_access_token)
    absolute_redirect_uri = f"https://{request.get_host()}{redirect_uri}"
    state = str(uuid.uuid4())
    request.session['state'] = state
    authcodeurl = bb.get_auth_url(scope='read write delete offline', redirect_uri=absolute_redirect_uri, state=state)
    logging.info(f"GET_AUTH_CODE: AUTHCODEURL:{authcodeurl}")
    logging.info(f"GET_AUTH_CODE: And now the app is setup to act on behalf of the user.")

    return HttpResponseRedirect(authcodeurl)

# [DONE]
def isup(request):
    return render(request, 'isup.html')

# [DONE]
def learnlogout(request):
    logging.info("LEARNLOGOUT: Flushing session and redirecting to Learn for logout")
    site_domain = request.META['HTTP_HOST']
    response = HttpResponse("Cookies Cleared")
    response.delete_cookie(site_domain)
    request.session.flush()
    return HttpResponseRedirect(f"https://{LEARNFQDN}/webapps/login?action=logout")

# [DONE]
def notauthorized(request):
    context = {}
    return render(request, 'notauthorized.html', context=context )

# [DONE] Retrieve User data
def getUser(request):
    # returns a list of one user - saves on javascript side.
    searchBy = request.GET.get('searchBy')
    searchValueUsr = request.GET.get('searchValueUsr')
    if (searchValueUsr is not None):
        searchValueUsr = searchValueUsr.strip()
    print ("getUser: SEARCHBY: ", searchBy)
    print ("getUser: SEARCHVALUEUSR: ", searchValueUsr)

    BbRestSetup(request, targetView='users', redirectRequired=True)

    usr = ""

    if (searchBy == 'externalId'):
        usr="externalId:" + searchValueUsr
    elif (searchBy == 'userName'):
        usr="userName:" + searchValueUsr
    
    print(f"user pattern: {usr}")
    
    #Process request... 
    resp = bb.GetUser(userId = usr, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True )
    if (resp.status_code == 200):
        user_json = resp.json() 
        dskresp = bb.GetDataSource(dataSourceId = user_json['dataSourceId'], sync=True)
        dsk_json = dskresp.json()
        user_json['dataSourceId'] = dsk_json['externalId']
        user_json['searchValueUsr'] = searchValueUsr
        user_json['searchBy'] = searchBy
        dskresp = bb.GetDataSources(limit = 5000, params={'fields':'id, externalId'}, sync=True)
        dsks_json = dskresp.json()
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks, 'externalId')

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

# [DONE] Update User data
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

    BbRestSetup(request, targetView='users', redirectRequired=True)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    #     request.session['target_view'] = 'users'
    #     return HttpResponseRedirect(reverse('get_auth_code'))
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #         whoami(request)
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'bbrest expiration: {bb.expiration()}')

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

# [DONE] Retrieve user list (based on DSK)
def getUsers(request):
    print ("NEW QUERY: getUsers")
    context = ""
    searchBy = request.GET.get('searchBy')
    searchValueUsr = request.GET.get('searchValueUsr')
    searchOptions = request.GET.get('searchOptions')
    searchAvailabilityOption = request.GET.get('searchAvailabilityOption')
    searchDate = request.GET.get('searchDate')
    searchDateOption = request.GET.get('searchDateOption')
    searchOptionList = None

    if (searchValueUsr is not None):
        searchValueUsr = searchValueUsr.strip()
        print ("GETUSERS SEARCHBY: ", searchBy)
    else:
        print("GETUSERS SEARCHBY NOT SET")
    if (searchValueUsr is not None):
        print ("GETUSERS SEARCHVALUEUSR: ", searchValueUsr)
    else:
        print("GETUSERS SEARCHVALUEUSR NOT SET")
    if (searchOptions is not None):
        print(f"GETUSERS SEARCHOPTIONS: ", searchOptions)
        searchOptionList = searchOptions.split(';')
        print(f"GETUSERS SEARCHOPTIONLIST: ", searchOptionList)
        print(f"IS BY AVAILABILITY A SELECTED OPTION? ", searchOptionList.count('searchAvailability'))
        print(f"IS BY DATE A SELECTED OPTION? ", searchOptionList.count('date'))
    else:
        print("GETUSERS SEARCHOPTIONLIST NOT SET")
    if (searchAvailabilityOption is not None):
        print(f"GETUSERS searchAvailabilityOption: ", searchAvailabilityOption)
    else:
        print("GETUSERS searchAvailabilityOption NOT SET")
    if (searchDate is not None):
        print(f"GETUSERS searchDate: ", searchDate)
    else:
        print("GETUSERS searchDate NOT SET")
    if (searchDateOption is not None):
        print(f"GETUSERS searchDateOption: ", searchDateOption)
    else:
        print("GETUSERS searchDateOption NOT SET")
    print (f"GETUSERS REQUEST:\n", request)
    isFoundStatus = False
    searchByDate = False
    searchByAvailability = False
    filterByAvailability = False
    filterByDSK = False

    if (searchOptions is not None):
        if searchOptionList.count('date') == 1: searchByDate = True
        if searchOptionList.count('availability') == 1: searchByAvailability = True
    print("SEARCH OPTIONS: byAvailability: ",  searchByAvailability, "byDate: ", searchByDate)

    BbRestSetup(request, targetView='users', redirectRequired=True)

    #currently not supporting any allUsers searches and we only use the date picker on DSK searches...

    if searchBy == 'DSK':
        if searchByDate:
            # use searchDate parameter
            #...
            print("SEARCH FOR ALL USERS USING DATE...")

            resp = bb.GetUsers(limit = 500000, params = {'created': searchDate,'createdCompare': searchDateOption,'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created, modified'}, sync=True )

            filterByDSK = True
            
            if searchByAvailability: filterByAvailability = True
            else: filterByAvailability = False
        else:
            # Not by date request, just do a standard request and return everything and filter on availability if requested
            #...
            resp = bb.GetUsers(limit = 500000, params = {'dataSourceId': searchValueUsr, 'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created, modified'}, sync=True )

            filterByDSK = False

            if searchByAvailability: filterByAvailability = True
            else: filterByAvailability = False
    """ else: 
        # eventually we will support an allUsers search as below
        # do a normal search and return everything...
        resp = bb.GetUsers(limit = 500000, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created'}, sync=True ) """

    # Otherwise search is by specifics in which case getUser was called and which should just return single user.

    # in either case we process the results filtering out undesired DSKs and availability options if requested...
    
    if (resp.status_code == 200):
        users_json = resp.json()
        print (f"USER COUNT(prepurge): ", len(users_json["results"]))

        dsksResp = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks, 'externalId')

        if filterByAvailability: 
            # filter resp by selected availability...
            print("GETUSERS EXECUTE AVAILABILITY PURGE")
            print("AVAILABILITY OPTION: ", searchAvailabilityOption)
            purgedResults = availabilityPurge(users_json,searchAvailabilityOption)
            # print("FILTERBYAVAILABILITY PURGED AVAILABILITY RESULTS:\n", purgedResults)
            print("FILTERBYAVAILABILITY PURGED RESULTS COUNT: ", len(purgedResults["results"]))
            users_json = purgedResults

        if filterByDSK:
            # filter resp by selected date...
            print("PURGING RESULTS based on DSK")
            purgedResults = datasourcePurge(users_json, searchValueUsr)
            # print("FILTERBYDSK PURGED DSK RESULTS:\n", purgedResults)
            print("FILTERBYDSK PURGED RESULTS COUNT: ", len(purgedResults["results"]))
            users_json = purgedResults

        users_json["length"] = len(users_json)  
        # print("DATASOURCE PURGE: users_json: /n", users_json)
        print("users_json SIZE: ", len(users_json))

        # we always want to replace dsk primary keys with the dsk externalId...  
        for idx, user in enumerate(users_json["results"]):
            for dsk in dsks:
                #print("DSK:\n", dsk)
                #print("DSKID: ", dsk["id"])
                if (dsk["id"] == user["dataSourceId"]):
                    users_json["results"][idx]["dataSourceId"] = dsk["externalId"]

    print("USERS_JSON TYPE: ", type(users_json))
    print("DSKS TYPE: ", type(dsks))

    context = {
        'users_json': users_json,
        'dsks_json': dsks,
    }

    return JsonResponse(context)

# [DONE] Update selected users from user list (based on DSK)
#   take request and iterate over each selected item, calling update user
#   concatenate result into error and success context
#   when done return context for processing in the UI

def updateUsers(request):  
    context = ""
    finalResponse = {}
    isFoundStatus = False
    resps = {'results':[]}
    print("RESPS SET TO EMPTY RESULTS")

    print("UPDATE USERS...")
    print ('updateUsers: Request:\n ')
    # print (request)
    print("updateUsers: isUpdateRequired1: ", request.GET.get("isUpdateRequired1"))
    print("updateUsers: isAvailabilityUpdateRequired1:", request.GET.get("isAvailabilityUpdateRequired1"))
    print("updateUsers: selectedAvailability: ", request.GET.get("selectedAvailability"))
    print("updateUsers: isDataSourceKeyUpdateRequired1: ", request.GET.get("isDataSourceKeyUpdateRequired1"))
    selectedDSK = request.GET.get("selectedDataSourceKey")
    print("updateUsers: selectedDataSourceKey: ", selectedDSK)
    print("updateUsers: pmcUserId[]: " + request.GET.get("pmcUserId[]"))
    updateList = request.GET.get('pmcUserId[]')
    print("updateUsers: updateList: ", updateList)
    updateUserList = updateList.split(',')

    passedPayload={}

    if (request.GET.get('isAvailabilityUpdateRequired1')):
        if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
            print("updateUsers: AVAILABILITY UPDATE REQUIRED")
            passedPayload={'availability':{"available":request.GET.get('selectedAvailability')}}
    if (request.GET.get('isDataSourceKeyUpdateRequired1')):
        if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
            passedPayload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
            print("updateUsers: DATASOURCE UPDATE REQUIRED")
            
    print ("updateUsers: PASSABLE PAYLOAD:\n", passedPayload)

    BbRestSetup(request, targetView='users', redirectRequired=True)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    #     request.session['target_view'] = 'users'
    #     return HttpResponseRedirect(reverse('get_auth_code'))
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #         whoami(request)
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'bbrest expiration: {bb.expiration()}')

    dsks_json = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    for x in range(len(updateUserList)): 
        print ("userPK: ", updateUserList[x])
        updateValue = updateUserList[x]
        # updateUser
        resp = bb.UpdateUser(userId = updateValue, payload=passedPayload, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, modified'}, sync=True )

        respJSON = resp.json()

        if (resp.status_code == 200):
            print("RESP:\n", resp.json())
            #resps["results"].append(respJSON["results"])
            print("RESPJSON:\n", respJSON)
            print("RESPJSON:dataSourceId", respJSON["dataSourceId"])
            isFoundStatus = True
            for dsk in dsks:
                # print("DSK:\n", dsk)
                # print("DSKID: ", dsk["id"])
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
                "result_json": resps["results"],
            }

        print("FINAL RESPONSE:\n", finalResponse)
    # STOPPED HERE
    return JsonResponse(finalResponse) 


# [DONE] Sorts the DSK list
def sortDsk(dsks, sortBy):
  return sorted(dsks, key=lambda x: x[sortBy])

# [DONE]
def guestusernotallowed(request):
    context = {
        'learn_server': LEARNFQDN,
    }   
    return render(request, 'guestusernotallowed.html', context=context )

# [DONE]
def error_500(request):
    data = {}
    return render(request,'error_500.html', data)

# [DONE]
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

    BbRestSetup(request, redirectRequired=True)
    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    #     return HttpResponseRedirect(reverse('get_auth_code'))
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')

    dsks_json = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'}).json()
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

# [DONE] Legacy - replaced...
# def validate_userIdentifier(request):
#     task = request.GET.get('task')
#     searchBy = request.GET.get('searchBy') #externalId || userName
#     searchValue = request.GET.get('searchValue')
#     if (searchValue is not None):
#         searchValue = searchValue.strip()
#     print("validate_userIdentifier: LEARNFQDN", LEARNFQDN)
#     print ("validate_userIdentifier: SEARCHBY: ", searchBy)
#     print ("validate_userIdentifier: SEARCHVALUE: ", searchValue)
#     print ("validate_userIdentifier: TASK: ", task)
    
#     if (searchBy == 'externalId'):
#         usr = "externalId:" + searchValue
#     else:
#         usr = "userName:" + searchValue

#     print(f"user pattern: {usr}")

#     try:
#         bb_json = request.session.get('bb_json')
#         if (bb_json is None):
#             bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
#             bb_json = jsonpickle.encode(bb)
#             print('pickled BbRest putting it on session')
#             request.session['bb_json'] = bb_json
#         else:
#             print('got BbRest from session')
#             bb = jsonpickle.decode(bb_json)
#             if bb.is_expired():
#                 print('expired token')
#                 request.session['bb_json'] = None
#             bb.supported_functions() # This and the following are required after
#             bb.method_generator()    # unpickling the pickled object.
#             print(f'expiration: {bb.expiration()}')

#     except:
#         data = {
#             'error_result': "Your 3LO session has expired. Please use the 'Learn Logout' link to the left, log back into Learn, and reload the DSKTOOL."
#         }

#     return JsonResponse(data)

    
#     validationresult = bb.GetUser(userId = usr, params = {'fields':'id, userName, name.given, name.middle, name.family, externalId, contact.email, availability.available, dataSourceId, created'}, sync=True )

#     print("VALIDATIONRESULT_STATUS: ", validationresult.status_code)
#     print(f"VALIDATIONRESULT:\n", validationresult.json())

#     #Use asynchronous when processing requests
#     # tasks = []
#     # for user in users:
#     #     tasks.append(bb.GetUser(user), sync=False)
#     #     resps = await asynchio.gather(*tasks)

#     if (validationresult.status_code == 200):
#         foundStatus = True
#     else:
#         foundStatus = False
    
#     data = {
#         'is_found': foundStatus
#     }

#     return JsonResponse(data)

# [DONE]
# def validate_courseIdentifier(request):
#     print("validate_courseIdentifier called....")
#     task = request.GET.get('task')
#     searchBy = request.GET.get('searchBy') #externalId || userName
#     searchValue = request.GET.get('searchValue')
#     if (searchValue is not None):
#         searchValue = searchValue.strip()
#     print("LEARNFQDN", LEARNFQDN)
#     print ("validate_courseIdentifier: SEARCHBY: ", searchBy)
#     print ("validate_courseIdentifier: SEARCHVALUE: ", searchValue)
#     print ("validate_courseIdentifier: TASK: ", task)
    
#     if (searchBy == 'externalId'):
#         crs = "externalId:" + searchValue
#     else:
#         crs = "courseId:" + searchValue

#     BbRestSetup(request)
#     # bb_json = request.session.get('bb_json')
#     # if (bb_json is None):
#     #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
#     #     bb_json = jsonpickle.encode(bb)
#     #     print('pickled BbRest putting it on session')
#     #     request.session['bb_json'] = bb_json
#     # else:
#     #     print('got BbRest from session')
#     #     bb = jsonpickle.decode(bb_json)
#     #     if bb.is_expired():
#     #         print('expired token')
#     #         request.session['bb_json'] = None
#     #     bb.supported_functions() # This and the following are required after
#     #     bb.method_generator()    # unpickling the pickled object.
#     #     print(f'expiratXion: {bb.expiration()}')

    
#     validationresult = bb.GetCourse(courseId = crs, sync=True )

#     print("VALIDATIONRESULT_STATUS: ", validationresult.status_code)
#     print(f"VALIDATIONRESULT:\n", validationresult.json())

#     if (validationresult.status_code == 200):
#         foundStatus = True
#     else:
#         foundStatus = False
    
#     data = {
#         'is_found': foundStatus
#     }

#     return JsonResponse(data)

# [DONE]
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

    BbRestSetup(request)
    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')

    memberships_result = bb.GetCourseMemberships( courseId = crs, limit = 1500, params = {'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True )

    print("memberships_result status: ", memberships_result.status_code)
    membershipsResultJSON = memberships_result.json()
    print(f"\nmemberships_result:\n", membershipsResultJSON)

    if (memberships_result.status_code == 200):
        dsksResp = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        #print("DSKS_JSON: \n", dsks_json)
        dsks = dsks_json["results"]
        #print("DSKS: \n", dsks)
        dsks = sortDsk(dsks, 'externalId')
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

    BbRestSetup(request)
    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')

    
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

    BbRestSetup(request)
    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')

    
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

    BbRestSetup(request)
    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')

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
        dskresp = bb.GetDataSources(limit = 5000, params={'fields':'id, externalId'}, sync=True)
        dsks_json = dskresp.json()
        print ("DSKS:\n", dsks_json["results"])
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks, 'externalId')
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

    searchBy = request.GET.get('searchBy') 
    searchValue = request.GET.get('searchValue')
    filterByDSK = request.GET.get('filterByDSK')
    filterByDSKValue = request.GET.get('filterDSK')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print("LEARNFQDN", LEARNFQDN)
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)
    print ("filterByDSK: ", filterByDSK)
    print ("filterByDSKValue: ", filterByDSKValue)

    if (searchBy == 'externalId'):
        crs = "externalId:" + searchValue
    else:
        crs = "courseId:" + searchValue

    BbRestSetup(request)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')

    
    if (filterByDSK == "true"):
        memberships_result = bb.GetCourseMemberships( courseId = crs, limit = 1500, params = {'dataSourceId': filterByDSKValue, 'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, childCourseId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True )
    else:
        memberships_result = bb.GetCourseMemberships( courseId = crs, limit = 1500, params = {'expand': 'user', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, childCourseId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'}, sync=True )
    
    print("memberships_result status: ", memberships_result.status_code)
    membershipsResultJSON = memberships_result.json()
    print(f"\nmemberships_result:\n", membershipsResultJSON)


    if (memberships_result.status_code == 200):
        dsksResp = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        #print("DSKS_JSON: \n", dsks_json)
        dsks = dsks_json["results"]
        #print("DSKS: \n", dsks)
        dsks = sortDsk(dsks, 'externalId')
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
    print("\ngetCourseMember Called...")
    print("request method: ", request.method)

    finalResponse = {}
    isFoundStatus = False
    resps = {'results':[]}
    print("RESPS SET TO EMPTY RESULTS")

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

    BbRestSetup(request, redirectRequired=True)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    #     return HttpResponseRedirect(reverse('get_auth_code'))
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')

    dsks_json = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'}).json()
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

# [DONE] Update a list of course memberships
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

    BbRestSetup(request, redirectRequired=True)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    #     return HttpResponseRedirect(reverse('get_auth_code'))
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')

    dsks_json = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'}).json()
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

# [DONE] Retrieve a list of user memberships
def getUserMemberships(request):
    print("getUserMemberships Called...")
    print("request method: ", request.method)

    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    filterByDSK = request.GET.get('filterByDSK')
    filterByDSKValue = request.GET.get('filterDSK')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print("LEARNFQDN", LEARNFQDN)
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)
    print ("filterByDSK: ", filterByDSK)
    print ("filterByDSKValue: ", filterByDSKValue)

    if (searchBy == 'externalId'):
        usr = "externalId:" + searchValue
    else:
        usr = "userName:" + searchValue

    BbRestSetup(request)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')
   
    if (filterByDSK == "true"):
        memberships_result = bb.GetUserMemberships( userId = usr, limit = 1500, params = {'dataSourceId': filterByDSKValue, 'expand': 'course', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, course.name, childCourseId, course.externalId'}, sync=True )
    else:
        memberships_result = bb.GetUserMemberships( userId = usr, limit = 1500, params = {'expand': 'course', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, course.name, childCourseId, course.externalId'}, sync=True )       

    print("memberships_result status: ", memberships_result.status_code)
    membershipsResultJSON = memberships_result.json()
    print(f"\nmemberships_result:\n", membershipsResultJSON)

    if (memberships_result.status_code == 200):
        dsksResp = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        #print("DSKS_JSON: \n", dsks_json)
        dsks = dsks_json["results"]
        #print("DSKS: \n", dsks)
        dsks = sortDsk(dsks, 'externalId' )
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

# [DONE] Update a list of user memberships
def updateUserMemberships(request):
    # {"crsSearchBy":"not_required","crsToSearchFor":"not_required","usrToSearchFor":"moneil","usrSearchBy":"externalId","isUpdateRequired1":"true","isAvailabilityUpdateRequired1":"true","selectedAvailability":"Yes","isDataSourceKeyUpdateRequired1":"true","selectedDataSourceKey":"_7_1","pmcUserId[]":["_9682_1:_1354_1","_9681_1:_1354_1"],"crsorusr":"byUsr"}
    finalResponse = {}
    print("request method: ", request.method)
    print("request: ", request)

    crsArray =  request.GET.getlist('pmcUserId[]')
    print("REQUEST pmcUsersList: \n", crsArray)

    BbRestSetup(request, redirectRequired=True)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    #     return HttpResponseRedirect(reverse('get_auth_code'))
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')

    dsks_json = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'}).json()
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

# [INPROGRESS] Retrieve a single course data - called from users page
def getCourse(request):
    # returns a list of one course - saves on javascript side.

    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)

    BbRestSetup(request, 'users', redirectRequired=True)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    #     request.session['target_view'] = 'users'
    #     return HttpResponseRedirect(reverse('get_auth_code'))
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #         whoami(request)
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')
     
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
        dskresp = bb.GetDataSources(limit = 5000, params={'fields':'id, externalId'}, sync=True)
        dsks_json = dskresp.json()
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks, 'externalId')
        
        isFoundStatus = True

        context = {
            'is_found': isFoundStatus,
            'result_json': course_json,
            'dsks_json': dsks,
        }

    else:
        error_json = resp.json()
        print (f"RESPONSE:\n", error_json)
        context = {
            'error_json': error_json,
        }

    return JsonResponse(context)

# [DONE] Update a single course - called from users page
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
    updateValue = request.GET.get('pmcCourseId[]')
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

    BbRestSetup(request, 'users', redirectRequired=True)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    #     request.session['target_view'] = 'users'
    #     return HttpResponseRedirect(reverse('get_auth_code'))
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #         whoami(request)
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'bbrest expiration: {bb.expiration()}')

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

# [INPROGRESS] Retrieve course list (All or based on DSK)
# this method handles:
# Query by:
#   DSK
#   ALLCOURSES
# Additionally this method supports searching by:
#   DATE
#   AVAILABILITY
def getCourses(request):
    print ("NEW QUERY: getCourses")
    context = ""
    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    searchOptions = request.GET.get('searchOptions')
    searchAvailabilityOption = request.GET.get('searchAvailabilityOption')
    searchDate = request.GET.get('searchDate')
    searchDateOption = request.GET.get('searchDateOption')
    searchOptionList = None

    if (searchValue is not None):
        searchValue = searchValue.strip()
        print ("GETCOURSES SEARCHBY: ", searchBy)
    if (searchValue is not None):
        print ("GETCOURSES SEARCHVALUE: ", searchValue)
    if (searchOptions is not None):
        print(f"GETCOURSES SEARCHOPTIONS: ", searchOptions)
        searchOptionList = searchOptions.split(';')
        print(f"GETCOURSES SEARCHOPTIONLIST: ", searchOptionList)
        print(f"IS BY AVAILABILITY A SELECTED OPTION? ", searchOptionList.count('searchAvailability'))
        print(f"IS BY DATE A SELECTED OPTION? ", searchOptionList.count('date'))
    if (searchAvailabilityOption is not None):
        print(f"GETCOURSES searchAvailabilityOption: ", searchAvailabilityOption)
    if (searchDate is not None):
        print(f"GETCOURSES searchDate: ", searchDate)
    if (searchDateOption is not None):
        print(f"GETCOURSES searchDateOption: ", searchDateOption)
    print (f"GETCOURSES REQUEST:\n", request)
    isFoundStatus = False
    searchByDate = False
    searchByAvailability = False
    filterByAvailability = False
    filterByDSK = False

    if (searchOptions is not None):
        if searchOptionList.count('date') == 1: searchByDate = True
        if searchOptionList.count('availability') == 1: searchByAvailability = True
    print("SEARCH OPTIONS: byAvailability: ",  searchByAvailability, "byDate: ", searchByDate)

    BbRestSetup(request, targetView='courses', redirectRequired=True)

    #if search request is by allcourses...
    if searchBy == 'allcourses':
        if searchByDate:
            # use searchDate parameter
            print("SEARCH FOR ALL COURSES USING DATE...")
            resp = bb.GetCourses(limit = 500000, params = {'created': searchDate,'createdCompare': searchDateOption, 'fields':'id, courseId, externalId, name, organization, availability.available, dataSourceId, modified, hasChildren, parentId'}, sync=True )
            filterByDSK = False
            if searchByAvailability: filterByAvailability = True
            else: filterByAvailability = False
        # elif searchByAvailability:
        #     # use searchAvailability parameter
        #     print("SEARCH FOR ALL COURSES USING AVAILABILTY...")
        #     resp = bb.GetCourses(limit = 500000, params = {'availability.available': searchAvailabilityOption, 'fields':'id, courseId, externalId, name, organization, availability.available, dataSourceId, modified'}, sync=True )

        else : # Not by date request, just do a standard request and return everything and filter on availability if requested
            print("SEARCH FOR ALL COURSES and FILTER ON AVAILABILITY if requested...")
            resp = bb.GetCourses(limit = 500000, params = {'fields':'id, courseId, externalId, name, organization, availability.available, dataSourceId, modified, hasChildren, parentId'}, sync=True )
            filterByDSK = False
            if searchByAvailability: filterByAvailability = True
            else: filterByAvailability = False

    elif searchBy == "DSK" : # we want courses with a specific DSK
        if searchByDate : 
            # Search by Date then filter results by availability, then purge DSKs
            print("GETCOURSES EXECUTE DATE SEARCH on DSK search; Then purge non-matching DSKs")
            resp = bb.GetCourses(limit = 500000, params = {'created': searchDate,'createdCompare': searchDateOption, 'fields':'id, courseId, externalId, name, organization, availability.available, dataSourceId, modified, hasChildren, parentId'}, sync=True )
            filterByDSK = True
            if searchByAvailability: filterByAvailability = True

        else: 
            print("GETCOURSES EXECUTE DSK ONLY SEARCH; Then filter on availability if selected...")

            # DSK post request filter only, just do a standard request and return everything.
            resp = bb.GetCourses(limit = 500000, params = {'dataSourceId': searchValue,'createdCompare': searchDateOption, 'fields':'id, courseId, externalId, name, organization, availability.available, dataSourceId, modified, hasChildren, parentId'}, sync=True )   
            filterByDSK = True # this is set to true to capture child courses that don't match the DSK...
            if searchByAvailability: filterByAvailability = True
            else: filterByAvailability = False

    # else: search is by specifics in which case getCourse was called and which should just return single courses. 
        
    if (resp.status_code == 200):
        courses_json = resp.json() 
        print (f"COURSES COUNT(prepurge): ", len(courses_json["results"]))
        
        # are we purging DSKs based on incoming option?
        # purge results based on options
        # if this is a DSK search we have already pulled the courses based on DSK
        dsksResp = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'})
        dsks_json = dsksResp.json()
        dsks = dsks_json["results"]
        dsks = sortDsk(dsks, 'externalId')

        if filterByAvailability: 
            # filter resp by selected availability...
            print("GETCOURSES EXECUTE AVAILABILITY PURGE")
            print("AVAILABILITY OPTION: ", searchAvailabilityOption)
            purgedResults = availabilityPurge(courses_json,searchAvailabilityOption)
            print("FILTERBYAVAILABILITY PURGED AVAILABILITY RESULTS:\n", purgedResults)
            print("FILTERBYAVAILABILITY PURGED RESULTS COUNT: ", len(purgedResults["results"]))
            courses_json = purgedResults

        if filterByDSK:
            # filter resp by selected date...
            print("PURGING RESULTS based on DSK")
            purgedResults = datasourcePurge(courses_json, searchValue)
            print("FILTERBYDSK PURGED DSK RESULTS:\n", purgedResults)
            print("FILTERBYDSK PURGED RESULTS COUNT: ", len(purgedResults["results"]))
            courses_json = purgedResults

        courses_json["length"] = len(courses_json)  
        print("DATASOURCE PURGE: courses_json: /n", courses_json)
        print("courses_json SIZE: ", len(courses_json))


        # we always want to replace dsk primary keys with the dsk externalId...
        for idx, course in enumerate(courses_json["results"]):
            for dsk in dsks:
                #print("DSK:\n", dsk)
                #print("DSKID: ", dsk["id"])
                if (dsk["id"] == course["dataSourceId"]):
                    courses_json["results"][idx]["dataSourceId"] = dsk["externalId"]

        print("COURSES_JSON TYPE: ", type(courses_json))
        print("DSKS TYPE: ", type(dsks))

        context = {
            'result_json': courses_json,
            'dsks_json': dsks,
        }

    return JsonResponse(context)

# [DONE] Update selected courses from course list (based on DSK)
def updateCourses(request):
    print("UPDATE COURSES...")
    context = ""
    finalResponse = {}
    isFoundStatus = False
    resps = {'results':[]}
    print("RESPS SET TO EMPTY RESULTS")
    print ('updateCourses: Request:\n ')
    # print (request)
    print("updateCourses: isUpdateRequired1: ", request.GET.get("isUpdateRequired1"))
    print("updateCourses: isAvailabilityUpdateRequired1:", request.GET.get("isAvailabilityUpdateRequired1"))
    print("updateCourses: selectedAvailability: ", request.GET.get("selectedAvailability"))
    print("updateCourses: isDataSourceKeyUpdateRequired1: ", request.GET.get("isDataSourceKeyUpdateRequired1"))
    selectedDSK = request.GET.get("selectedDataSourceKey")
    print("updateCourses: selectedDataSourceKey: ", selectedDSK)
    print("updateCourses: pmcCourseId[]: " + request.GET.get("pmcCourseId[]"))
    updateList = request.GET.get('pmcCourseId[]')
    print("updateCourses: updateList: ", updateList)
    updateCourseList = updateList.split(',')

    print("updateCourses: updateCourseList: ", updateCourseList)

    passedPayload={}

    if (request.GET.get('isAvailabilityUpdateRequired1')):
        if (request.GET.get('isAvailabilityUpdateRequired1') == 'true'):
            print("updateCourses: AVAILABILITY UPDATE REQUIRED")
            passedPayload={'availability':{"available":request.GET.get('selectedAvailability')}}
    if (request.GET.get('isDataSourceKeyUpdateRequired1')):
        if (request.GET.get('isDataSourceKeyUpdateRequired1') == 'true'):
            passedPayload["dataSourceId"] = request.GET.get('selectedDataSourceKey')
            print("updateCourses: DATASOURCE UPDATE REQUIRED")
            
    print ("updateCourses: PASSABLE PAYLOAD:\n", passedPayload)

    BbRestSetup(request, targetView='courses', redirectRequired=True)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    #     request.session['target_view'] = 'courses'
    #     return HttpResponseRedirect(reverse('get_auth_code'))
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #         whoami(request)
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'bbrest expiration: {bb.expiration()}')

    dsks_json = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'}).json()
    dsks = dsks_json["results"]

    for x in range(len(updateCourseList)): 
        print ("coursePK: ", updateCourseList[x])
        updateValue = updateCourseList[x]
        # updateCourse
        resp = bb.UpdateCourse(courseId = updateValue, payload=passedPayload, params = {'fields':'id, courseId, externalId, name, availability.available, dataSourceId, created'}, sync=True )

        respJSON = resp.json()

        if (resp.status_code == 200):
            print("RESP:\n", resp.json())
            #resps["results"].append(respJSON["results"])
            print("RESPJSON:\n", respJSON)
            print("RESPJSON:dataSourceId", respJSON["dataSourceId"])
            isFoundStatus = True
            for dsk in dsks:
                # print("DSK:\n", dsk)
                # print("DSKID: ", dsk["id"])
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
                "result_json": resps["results"],
            }

        print("FINAL RESPONSE:\n", finalResponse)
    # STOPPED HERE
    return JsonResponse(finalResponse) 

# [IN PROGRESS] Retrieve membership list (based on DSK)
def getMembershipsByDSK(request):
    print ("GET MEMBERSHIPS BY DSK CALLED")
    print("request method: ", request.method)

    searchBy = request.GET.get('searchBy')
    searchValue = request.GET.get('searchValue')
    crsAvailFilter = request.GET.get('crsAvailFilter')
    # pmc = request.GET.get('searchValue')
    if (searchValue is not None):
        searchValue = searchValue.strip()
    print("LEARNFQDN", LEARNFQDN)
    print ("SEARCHBY: ", searchBy)
    print ("SEARCHVALUE: ", searchValue)
    print ("CRSAVAILFILTER: ", crsAvailFilter)

    isFoundStatus = False

    BbRestSetup(request)

    # bb_json = request.session.get('bb_json')
    # if (bb_json is None):
    #     bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
    #     bb_json = jsonpickle.encode(bb)
    #     print('pickled BbRest putting it on session')
    #     request.session['bb_json'] = bb_json
    # else:
    #     print('got BbRest from session')
    #     bb = jsonpickle.decode(bb_json)
    #     if bb.is_expired():
    #         print('expired token')
    #         request.session['bb_json'] = None
    #     bb.supported_functions() # This and the following are required after
    #     bb.method_generator()    # unpickling the pickled object.
    #     print(f'expiration: {bb.expiration()}')

    # First get course list based on crsAvailFilter
    # Then get memberships for each course based on DSK filter


    memberships_result = bb.GetMemberships(limit = 500000, params = {'datasource': 'searchValue', 'expand': 'course', 'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, courseRoleId, course.name, childCourseId, course.externalId'}, sync=True )

    # print("memberships_result status: ", memberships_result.status_code)
    membershipsResultJSON = memberships_result.json()
    # print(f"\nmemberships_result:\n", membershipsResultJSON)

    context = {
        "is_found": isFoundStatus,
        'result_json': membershipsResultJSON,
    }

    return JsonResponse(context)

# [DONE] Retrieve the full list of Data Source Keys
def getDataSourceKeys(request):
    print (f"getDataSourceKeys request:\n", request)

    BbRestSetup(request)

    resp = bb.GetDataSources(limit = 5000, params = {'fields': 'id, externalId'}, sync=True )

    isFoundStatus = False
    if (resp.status_code == 200):
        result_json = resp.json() #return actual error
        
        print(f"GET DSKS RESP: \n", resp.json())
        print(f"DSK COUNT: ", len(result_json["results"]))

        dsks = result_json["results"]
        dsks = sortDsk(dsks, 'externalId')
    
        isFoundStatus = True

        context = {
          "is_found": isFoundStatus,
          'result_json': dsks,
        }
    else:
        error_json = resp.json()
        print (f"ERROR RESPONSE:\n", error_json)
        context = {
            "is_found": isFoundStatus,
            'error_json': error_json,
        }

    return JsonResponse(context)

# [IN PROGRESS] Take a response and refactor, purging unwanted DSKs
# called by any COLLECTION request requiring availability as a search option e.g. getCourses, getUsers
#  purgedResults = datasourcePurge(resp, searchValue)

def datasourcePurge(resp, dataSourceOption):
    dataSourceToKeep = dataSourceOption
    purgedResponse = { "results": [] }
    #dataSourceExternalId = dskList[dataSourceToKeep]["externalId"]
    print("CALLED DATASOURCEPURGE...")
    print("DATASOURCE PURGE: datasourceOption: ", dataSourceToKeep)
    print("RESP:\n", resp)
    #print("DATASOURCE EXTERNALID: ", dataSourceExternalId)

    #iterate over resp, and remove any records not matching the datasourceOption
    # if result:dataSourceId == datasourceToKeep then update the dataSourseExternalId.
    items=purgedResponse["results"]

    for idx, item in enumerate(resp["results"]):
        if (item["dataSourceId"] == dataSourceToKeep):
            print("ITEM: ", item)
            print(type(item))
            items.append(item)
            if "hasChildren" in item and item["hasChildren"] == True:
                #get children and add to items
                print("GET ITEM CHILDREN.")
                children = bb.GetCourseChildren(courseId=item["id"], limit = 500000, params = { 'fields':'childCourse.id, childCourse.courseId, childCourse.externalId, childCourse.name, childCourse.organization, childCourse.availability.available, childCourse.dataSourceId, childCourse.created, childCourse.hasChildren, childCourse.parentId'}, sync=True )
                if (children.status_code == 200):
                    children_json = children.json()
                    for idx2, child in enumerate(children_json["results"]):
                        child["childCourse"]["modified"] = child["childCourse"]["created"]
                        print("CHILD: ", child["childCourse"])
                        items.append(child["childCourse"])

    print("DATASOURCE PURGE PURGEDRESPONSE SIZE: ", len(purgedResponse))
    
    return purgedResponse

def availabilityPurge(resp, searchAvailabilityOption):
    availabilityToKeep = searchAvailabilityOption
    purgedResponse = { "results": [] }

    print("Called availabilityPurge")
    print("AVAILABILITY PURGE: searchAvailabilityOption: ", availabilityToKeep)
    #dataSourceExternalId = dskList[dataSourceToKeep]["externalId"]
    #iterate over resp, and remove any records not matching the datasourceOption
    # if result:dataSourceId == datasourceToKeep then update the dataSourseExternalId.
    items=purgedResponse["results"]

    for idx, item in enumerate(resp["results"]):
        itemAvailability=item["availability"]["available"]
        print("ITEM AVAILABILITY: ", itemAvailability.upper())
        if (item["availability"]["available"].upper() == availabilityToKeep.upper()):
            print("ITEM: ", item)
            print(type(item))
            items.append(item)
    # print("AVAILABILITY PURGE: purgedResponse: ", purgedResponse)
    print("AVAILABILITY PURGE PURGEDRESPONSE SIZE: ", len(purgedResponse))

    return purgedResponse

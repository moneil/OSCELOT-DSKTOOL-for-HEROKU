from django.http import HttpResponseRedirect
from bbrest import BbRest
import jsonpickle
import json
from dsktool.models import Messages
from dsktool.models import Logs

class Rfc(object):
	"""
		Request for change class
		Record the reason for change in local sqllite3 database
	"""
	def __init__(self):
		super(Rfc, self).__init__()

	# save the message input for the Rfc
	def save_message(self, request, change_type):
		bb = self.get_bb(request)
		me_resp = bb.call(
			'GetUser',
			userId = "me",
			params = {'fields':'id, userName'},
			sync = True
			)

		me_json = me_resp.json()

		message = Messages(
			user_id = me_json['userName'],
			change_type = change_type,
			change_comment = request.GET.get('comment')
		)
		message.save()

		return message

	def save_log(self, **kwargs):
		json = self.solve_for(
			self,
			call_name = kwargs.get('call_name',""),
			userSearch = kwargs.get('userSearch',""),
			request = kwargs.get('request',""),
			crs = kwargs.get('crs',""),
			usr = kwargs.get('usr',""),
			updateValue = kwargs.get('updateValue',""),
		)

		if kwargs.get('call_name',"") == "user":
			log = Logs(
				message = kwargs.get('message',{}),
				user_id = json['user_json']['userName'],
				external_id = json['user_json']['externalId'],
				availability_status = json['user_json']['availability']['available'],
				datasource_id = self.get_datasource(self, request=kwargs.get('request',""),dataSourceId=json['user_json']['dataSourceId']),
				state = kwargs.get('state',"")
			)
		elif kwargs.get('call_name',"") == "membership":
			log = Logs(
				message = kwargs.get('message',{}),
				user_id = json['enroll_json']['user']['userName'],
				course_id = json['course_json']['courseId'],
				external_id = json['enroll_json']['user']['externalId'],
				course_role = json['enroll_json']['courseRoleId'],
				availability_status = json['enroll_json']['availability']['available'],
				datasource_id = self.get_datasource(self, request=kwargs.get('request',""),dataSourceId=json['enroll_json']['dataSourceId']),
				state = kwargs.get('state',"")
			)
		elif kwargs.get('call_name',"") == "course":
			log = Logs(
				message = kwargs.get('message',{}),
				course_id = json['course_json']['courseId'],
				external_id = json['course_json']['externalId'],
				availability_status = json['course_json']['availability']['available'],
				datasource_id = self.get_datasource(self, request=kwargs.get('request',""),dataSourceId=json['course_json']['dataSourceId']),
				state = kwargs.get('state',"")
			)
		log.save()

	@staticmethod
	def get_bb(request):
		bb_json = request.session.get('bb_json')
		if (bb_json is None):
			bb = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
			bb_json = jsonpickle.encode(bb)
			request.session['bb_json'] = bb_json
			request.session['target_view'] = 'users'
			return HttpResponseRedirect(reverse('get_auth_code'))
		else:
			bb = jsonpickle.decode(bb_json)
			if bb.is_expired():
				request.session['bb_json'] = None
				whoami(request)
			bb.supported_functions() # This and the following are required after
			bb.method_generator()    # unpickling the pickled object.

		return bb

	@staticmethod
	def get_user(self, **kwargs):
		bb = self.get_bb(kwargs.get('request',""))
		user_resp = bb.GetUser(
			userId = kwargs.get('userSearch',""),
			params = {
				'fields': 'id, userName, externalId, availability.available, dataSourceId'
			},
			sync=True
		)

		return {"user_json" : user_resp.json()}

	@staticmethod
	def get_membership(self, **kwargs):
		bb = self.get_bb(kwargs.get('request',""))
		enroll_resp = bb.GetMembership(
			courseId = kwargs.get('crs',""),
			userId = kwargs.get('usr',""),
			params = {
				'expand': 'user',
				'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, created, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'
			},
			sync=True
		)

		course_resp = bb.GetCourse(
			courseId = kwargs.get('crs',""),
			params = {
				'fields':'id, courseId'
			},
			sync=True
		)

		return {
			"enroll_json" : enroll_resp.json(),
			"course_json" : course_resp.json()
		}

	@staticmethod
	def get_course(self, **kwargs):
		bb = self.get_bb(kwargs.get('request',""))
		course_resp = bb.GetCourse(
			courseId = kwargs.get('updateValue',""),
			params = {
				'fields': 'id, courseId, externalId, availability.available, dataSourceId'
			},
			sync=True
		)

		return {"course_json" : course_resp.json()}

	@staticmethod
	def get_datasource(self, **kwargs):
		bb = self.get_bb(kwargs.get('request',""))
		resp = bb.GetDataSource(
			dataSourceId = kwargs.get('dataSourceId',""),
			params = {
				'fields': 'id, externalId'
			},
			sync=True
		)

		return resp.json()['externalId']

	@staticmethod
	def solve_for(self, call_name: str, **kwargs):
		do = f"get_{call_name}"
		if hasattr(self, do) and callable(func := getattr(self, do)):
			return func(self, **kwargs)

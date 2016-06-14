import bcrypt, falcon, json, pprint, re, time
from datetime import datetime
from jose import jwt

from models import User, List, Item, db
from secret import secret


# Frequently used labels
TITLE = 'title'
DESCRIPTION = 'description'
USER = 'user'
NAME = 'name'
EMAIL = 'email'
PASSWORD = 'password'
ID = 'id'
PUBLIC = 'public'
NUMBER = 'number'
ITEM = 'item'
LISTS = 'lists'
USERID = 'userId'
LISTID = 'listId'


########## UTILITY METHODS ##########

# Authenticate requests (for requests that require it)
def authenticate(req, res, resource, params):
	def supply_valid_token():
		raise falcon.HTTPUnauthorized('Auth token required',
			'Please provide a valid auth token in the request\'s '
			'Authorization header.',
			['Token type="JWT"'])

	def forbidden():
		raise falcon.HTTPForbidden('Permission denied',
			'You are not authorized to perform this action. '
			'This resource does not seem to belong to you.')

	try:
		token = req.auth.replace('Bearer ', '').strip()
	except:
		supply_valid_token()

	# Is the token properly signed?
	try:
		decoded = jwt.decode(token, secret)
	except jwt.JWTError:
		supply_valid_token()

	# Is the user allowed to see this resource?
	try:
		user = decoded['sub'] # userId
		if USERID in params and user != params[USERID]:
			forbidden()
		elif LISTID in params:
			collection = (List
				.select()
				.join(User)
				.where(List.id == params[LISTID]))
			if collection.exists():
				collection = collection.get()
				owner = collection.owner.id
				if str(user) != str(owner) and collection.public == 0:
					forbidden()
	except KeyError:
		supply_valid_token()

	# Is the token expired?
	try:
		exp = decoded['exp']
		if time.gmtime(exp) < time.gmtime(): # if token is expired
			raise falcon.HTTPUnauthorized('Authorization expired',
				'Your auth token has expired.',
				['Token type="JWT"'])
	except (KeyError, TypeError):
		raise falcon.HTTPUnauthorized('Auth expiration required',
			'Your auth token does not contain a valid expiration time. '
			'Please request a new auth token.',
			['Token type="JWT"'])

	params[USERID] = user


def parse_json(req):
	try:
		return json.loads(req.stream.read())
	except ValueError:
		raise falcon.HTTPBadRequest('JSON decode error',
			'The supplied JSON could not be decoded. '
			'Please supply valid JSON.')


def validate_posted_json(req, **kwargs):
	j = parse_json(req)

	if kwargs is None:
		return j

	for field, required in kwargs.iteritems():
		if required and field not in j:
			raise falcon.HTTPBadRequest('JSON missing {}.'.format(field),
				'The supplied JSON did not include a "{}" field. '
				'Please supply a "{}" field.'.format(field, field))
		elif field not in j:
			j[field] = None

	return j


########## MIDDLEWARE ##########

# Ensure database connection is opened and closed for each request
class DBConnectMiddleware(object):

	def process_request(self, req, res):
		db.connect()

	def process_response(self, req, res, resource):
		if not db.is_closed():
			db.close()


########## RESOURCES ##########

# /user/register
class UserRegistrationResource(object):

	def on_post(self, req, res):
		j = validate_posted_json(req, email=True, password=True, name=True)

		email, password, name = j[EMAIL], j[PASSWORD], j[NAME]

		if not self._validate_password(password):
			raise falcon.HTTPBadRequest('Invalid password',
				'Your password must be at least 8 characters '
				'and contain at least 1 number or symbol.')

		password = bcrypt.hashpw(password.encode('utf-8'),
			bcrypt.gensalt()) # hash the password

		user = User.select().where(User.email == email)

		if user.exists():
			raise falcon.HTTPConflict('Email in use',
				'The email address you provided is already in use.')
		else:
			r = User(email=email,
				password=password,
				name=name).save()
			if r == 0:
				falcon.HTTPInternalServerError('Error saving user',
					'There was an unknown error saving your '
					'account details. Please try again later.')

		res.status = falcon.HTTP_200
			
	def _validate_password(self, password):
		return (
			len(password) > 8
			and len(re.sub('[A-Za-z]', '', password)) > 0
		)

# /user/login
class UserResource(object):

	def on_post(self, req, res):
		j = parse_json(req)

		def invalid():
			raise falcon.HTTPUnauthorized('Invalid credentials',
				'Your login credentials are not correct. '
				'Please try again.',
				['Auth type="Password"'])

		try:
			email = j[EMAIL]
			password = j[PASSWORD]
		except KeyError:
			raise falcon.HTTPUnauthorized('Invalid credentials',
				'Your email and/or password was not sent correctly. '
				'Please try again.',
				['Auth type="Password"'])

		user = User.select().where(User.email == email)

		if not user.exists():
			invalid()

		user = user.get()
		if not user.password == bcrypt.hashpw(password.encode('utf-8'),
			user.password.encode('utf-8')):
			invalid()

		claims = {
			'iss': 'http://lister.com',
			'sub': str(user.id),
			'exp': time.time() + 3600 * 14 # expire in 2 weeks
		}
		token = jwt.encode(claims, secret, algorithm='HS256')

		res.body = token


# /user/{userId}
class UserInfoResource(object):

	def on_get(self, req, res, userId):
		user = User.select().where(User.id == userId)
		if not user.exists():
			raise falcon.HTTPNotFound()
		user = user.get()

		#r = {USER: user.id, NAME: user.name, EMAIL: user.email, LISTS: []}
		r = {USER: user.id, NAME: user.name, EMAIL: user.email}

		'''
		lists = List.select().where((List.owner == user) & (List.public == 1))
		for l in lists:
			r[LISTS].append({
				ID: l.id,
				TITLE: l.title,
				DESCRIPTION: l.description
			})
		'''

		res.body = json.dumps(r)

	@falcon.before(authenticate)
	def on_delete(self, req, res, userId):
		user = self._get_user(userId)
		user.delete_instance()
		
		res.status = falcon.HTTP_200
		
	def _get_user(self, userId):
		user = User.select().where(User.id == userId)
		if not user.exists():
			raise falcon.HTTPNotFound()
		return user.get()


# /user/{userId}/lists
class UserListsResource(object): 

	def on_get(self, req, res, userId):
		lists = List.select().where(List.owner == userId)
		lists = map(lambda l: l.id, lists)

		res.body = json.dumps(lists)


# /list/{listId}
@falcon.before(authenticate)
class ListResource(object):
	
	def on_get(self, req, res, listId, userId):
		collection = self._get_collection(listId)

		itemList = Item.select().where(Item.collection == collection)

		items = []
		for item in itemList:
			items.append({
				ITEM: item.id,
				TITLE: item.title, 
				DESCRIPTION: item.description
			})

		res.body = json.dumps({
			TITLE: collection.title,
			DESCRIPTION: collection.description,
			'items': items
		})
	
	def on_put(self, req, res, listId):
		collection = self._get_collection(listId)

		j = parse_json(req)

		if TITLE in j:
			collection.title = j[TITLE]
		if DESCRIPTION in j:
			collection.description = j[DESCRIPTION]

		updated = collection.save()

		res.status = falcon.HTTP_200

	def on_delete(self, req, res, listId, userId):
		collection = self._get_collection(listId)
		collection.delete_instance()
		
		res.status = falcon.HTTP_200

	def _get_collection(self, listId):
		collection = List.select().where(List.id == listId)
		if not collection.exists():
			raise falcon.HTTPNotFound()
		return collection.get()


# /list/new
@falcon.before(authenticate)
class ListCreateResource(object):

	def on_post(self, req, res, userId):
		j = validate_posted_json(req, title=True, description=False, public=False)

		title = j[TITLE]
		description = j[DESCRIPTION]
		public = j[PUBLIC]
		if public is None:
			public = 0

		listId = List.create(owner=userId,
			title=title,
			description=description,
			public=public).id

		res.body = json.dumps({ID: listId})


# /list/{listId}/add
@falcon.before(authenticate)
class ListItemAddResource(object):

	def on_post(self, req, res, listId, userId):
		j = validate_posted_json(req, title=True, description=False, number=False)

		title = j[TITLE]
		description = j[DESCRIPTION]
		number = j[NUMBER]

		if number is None:
			number = -1
		else: # push down all the items that come after this
			items = Item.select().where(Item.number >= number)
			for item in items:
				item.number += 1
				item.save()

		itemId = Item.create(collection=listId,
			title=title,
			description=description,
			number=number).id

		res.body = json.dumps({ID: itemId})


# /list/{itemId}
@falcon.before(authenticate)
class ListItemResource(object):
	
	def on_put(self, req, res, listId, itemId):
		item  = self._get_item(itemId)

		j = parse_json(req)

		if TITLE in j:
			item.title = j[TITLE]
		if DESCRIPTION in j:
			item.description = j[DESCRIPTION]

		updated = item.save()

		res.status = falcon.HTTP_200

	def on_delete(self, req, res, listId, itemId):
		item = self._get_item(itemId)
		item.delete_instance()
		
		res.status = falcon.HTTP_200

	def _get_item(self, itemId):
		item = Item.select().where(Item.id == itemId)
		if not item.exists():
			raise falcon.HTTPNotFound()
		return item.get()


# Add routes
app = falcon.API(middleware=[
	DBConnectMiddleware()
])

# User interactions
app.add_route('/user/register', UserRegistrationResource())
app.add_route('/user/login', UserResource())
app.add_route('/user/{userId}', UserInfoResource())
app.add_route('/user/{userId}/lists', UserListsResource())

# List interactions
app.add_route('/list/new', ListCreateResource())
app.add_route('/list/{listId}', ListResource())

# Item interactions
app.add_route('/list/{listId}/add', ListItemAddResource())
app.add_route('/item/{itemId}', ListItemResource())

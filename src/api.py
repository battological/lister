import bcrypt, falcon, json, time
from jose import jwt

from models import User, List, Item, db
from secret import secret


# Frequently used labels
TITLE = 'title'
DESCRIPTION = 'description'
USER = 'user'
NAME = 'name'
ID = 'id'
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
			owner = (List
				.select()
				.join(User)
				.where(List.id == params[LISTID])
				.get()
				.owner
				.id)
			if str(user) != str(owner):
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


def read_posted_json(req):
	j = parse_json(req)

	try:
		title = j[TITLE]
	except KeyError:
		raise falcon.HTTPBadRequest('JSON missing "title."',
			'The supplied JSON did not include a "title" field. '
			'Please supply a "title" field.')

	description = None
	if DESCRIPTION in j:
		description = j[DESCRIPTION]
	
	return (title, description)


########## MIDDLEWARE ##########

# Ensure database connection is opened and closed for each request
class DBConnectMiddleware(object):

	def process_request(self, req, res):
		db.connect()

	def process_response(self, req, res, resource):
		if not db.is_closed():
			db.close()


########## RESOURCES ##########

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
			email = j['email']
			password = j['password']
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

		r = {USER: user.id, NAME: user.name, LISTS: []}

		lists = List.select().where(List.owner == user)
		for l in lists:
			r[LISTS].append({
				ID: l.id,
				TITLE: l.title,
				DESCRIPTION: l.description
			})

		res.body = json.dumps(r)


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

	def on_delete(self, req, res, listId):
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
		title, description = read_posted_json(req)

		listId = List.create(owner=userId,
			title=title,
			description=description).id

		res.body = json.dumps({ID: listId})


# /list/{listId}/add
@falcon.before(authenticate)
class ListItemAddResource(object):

	def on_post(self, req, res, listId, userId):
		title, description = read_posted_json(req)

		itemId = Item.create(collection=listId,
			title=title,
			description=description).id

		res.body = json.dumps({ID: itemId})


# /list/{listId}/{itemId}
@falcone.before(authenticate)
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

	def _get_item(self, itemId)
		item = Item.select().where(Item.id == itemId)
		if not item.exists():
			raise falcon.HTTPNotFound()
		return item.get()


# Add routes
app = falcon.API(middleware=[
	DBConnectMiddleware()
])

# User interactions
app.add_route('/user/login', UserResource())
app.add_route('/user/{userId}', UserInfoResource())
app.add_route('/user/{userId}/lists', UserListsResource())

# List interactions
app.add_route('/list/new', ListCreateResource())
app.add_route('/list/{listId}', ListResource())

# Item interactions
app.add_route('/list/{listId}/add', ListItemAddResource())
app.add_route('/list/{listId}/{itemId}', ListItemResource())

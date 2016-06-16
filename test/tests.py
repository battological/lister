import sys, os.path
from webtest import TestApp

sys.path.append(os.path.abspath(os.path.join(
	os.path.dirname(__file__),
	os.path.pardir,
	'src')))
from api import app
from models import User


TEST = 'Testing'
GET = 'Getting'
POST = 'Posting'
PUT = 'Putting'
DELETE = 'Deleting'

def testing(url, verb=None):
	if verb is None:
		verb = TEST

	print('{} {}'.format(verb, url))

	return url

def standard_test(res):
	assert res.content_type == 'application/json'
	assert res.content_length > 0

def clear_user(email):
	user = User.select().where(User.email == email)
	if user.exists():
		user.get().delete_instance()


if __name__ == '__main__':

	app = TestApp(app)


	'''
	Start by clearing out the test data.
	With on delete cascade turned on, this should automatically clear
	   all testing data.
	'''
	clear_user('test@test.com')
	clear_user('alt@test.com')


	url = testing('/user/register', POST)

	res = app.post_json(url, {"email": "test@test.com",
		"password": "password1"},
		status=400)

	res = app.post_json(url, {"email": "test@test.com",
		"password": "password1",
		"name": "Tester"})
	userId = res.json['id']

	res = app.post_json(url, {"email": "test@test.com",
		"password": "password1",
		"name": "Tester"},
		status=409)

	res = app.post_json(url, {"email": "alt@test.com",
		"password": "password1",
		"name": "Alt"})
	altUserId = res.json['id']


	url = testing('/user/login', POST)
	res = app.post_json(url, {"email": "test@test.com", "password": "password1"})
	standard_test(res)
	assert res.json['id'] == userId

	token = res.json['jwt']
	assert len(token) > 0
	auth = {'Authorization': 'Bearer {}'.format(token)}

	res = app.post_json(url, {"email": "alt@test.com", "password": "password1"})
	token = res.json['jwt']
	altAuth = {'Authorization': 'Bearer {}'.format(token)}

	app.post_json(url,
		{"email": "wrong@nowhere.com", "password": "password1"},
		status=401)
	
	app.post_json(url,
		{"email": "test@test.com", "password": "wrongpassword"},
		status=401)


	url = testing('/list/new', POST)
	res = app.post_json(url,
		{"title": "Test list", "description": "This is my description"},
		headers=auth)
	added_list = res.json['id']

	res = app.post_json(url,
		{"title": "abc", "public": 1},
		headers=auth)
	public_list = res.json['id']
	
	url = testing('/user/{}/lists'.format(userId), GET)
	res = app.get(url)
	standard_test(res)

	lists = res.json
	assert len(lists) > 0


	url = testing('/user/{}'.format(userId), PUT)
	res = app.put_json(url, {"name": "Test2"}, status=401)
	res = app.put_json(url, {"name": "Test2"}, headers=altAuth, status=403)
	res = app.put_json(url, {"name": "Test2"}, headers=auth)


	url = testing('/list/{}'.format(added_list), GET)
	res = app.get(url, headers=auth)
	standard_test(res)

	res = app.get(url, headers=altAuth, status=403)
	res = app.get('/list/{}'.format(public_list), headers=altAuth)


	url = testing('/list/{}'.format(added_list), PUT)
	res = app.put_json(url, {"title": "Edited test list"}, headers=auth)

	res = app.get('/list/{}'.format(added_list), headers=auth)
	assert res.json['title'] == 'Edited test list' # should have changed
	assert res.json['description'] == 'This is my description' # should *not* have changed

	res = app.put_json(url, {"title": "Should fail"}, status=401)


	url = testing('/user/{}'.format(userId), GET)
	res = app.get(url)
	standard_test(res)


	'''
	url = testing('/list/{}'.format(str(i)))
	res = app.get(url, status=401)
	res = app.get(url, headers={'Authorization': 'Bearer {}'.format(token)}, status=403)
	'''

	
	url = testing('/list/{}/add'.format(added_list), POST)
	res = app.post_json(url, 
		{'title': 'Item2', 'description': 'Item2 desc', 'number': 2},
		headers=auth)
	standard_test(res)
	res = app.post_json(url,
		{'title': 'Item1', 'description': 'Item1 desc', 'number': 1},
		headers=auth)
	standard_test(res)
	res = app.post_json(url,
		{'title': 'Item12', 'description': 'Item12 desc', 'number': 1},
		headers=auth)
	itemId = res.json['id']
	res = app.post_json(url,
		{'title': 'Item-1', 'description': 'Item-1 desc', 'number': -1},
		headers=auth)
	
	res = app.post_json(url,
		{'title': 'Item3', 'description': 'Item3 desc', 'number': -1},
		status=401)


	url = testing('/list/{}'.format(added_list), GET)
	res = app.get(url, headers=auth)
	standard_test(res)
	assert res.json['items'][0]['title'] == 'Item12'
	assert res.json['items'][1]['title'] == 'Item1'
	assert res.json['items'][2]['title'] == 'Item2'
	assert res.json['items'][3]['title'] == 'Item-1'


	url = testing('/item/{}'.format(itemId), DELETE)
	app.delete(url, status=401)
	app.delete(url, headers=auth)
	res = app.get('/list/{}'.format(added_list), headers=auth)
	assert res.json['items'][0]['title'] == 'Item1'
	itemId = res.json['items'][0]['item']

	
	url = testing('/item/{}'.format(itemId), PUT)
	app.put(url, status=401)
	app.put_json(url, {'title': 'Item1!'}, headers=auth)
	res = app.get('/list/{}'.format(added_list), headers=auth)
	assert res.json['items'][0]['title'] == 'Item1!'

	
	url = testing('/list/{}'.format(added_list), DELETE)
	res = app.delete(url, headers=auth)

	# Ensure cascade delete worked
	app.delete('/item/{}'.format(itemId), headers=auth, status=404)


	url = testing('/user/{}'.format(userId), DELETE)
	res = app.delete(url, headers=auth)


	print('All tests passed!')

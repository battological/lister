import sys, os.path
from webtest import TestApp

sys.path.append(os.path.abspath(os.path.join(
	os.path.dirname(__file__),
	os.path.pardir,
	'src')))
from api import app


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

if __name__ == '__main__':

	app = TestApp(app)


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


	url = testing('/user/login', POST)
	res = app.post_json(url, {"email": "test@test.com", "password": "password1"})
	standard_test(res)
	assert res.json['id'] == userId

	token = res.json['jwt']
	assert len(token) > 0
	auth = {'Authorization': 'Bearer {}'.format(token)}

	app.post_json(url,
		{"email": "wrong@nowhere.com", "password": "password"},
		status=401)
	
	app.post_json(url,
		{"email": "test@test.com", "password": "wrongpassword"},
		status=401)


	url = testing('/list/new', POST)
	res = app.post_json(url,
		{"title": "Test list", "description": "This is my description"},
		headers=auth)
	added_list = res.json['id']
	
	url = testing('/user/{}/lists'.format(userId), GET)
	res = app.get(url)
	standard_test(res)

	lists = res.json
	assert len(lists) > 0


	url = testing('/list/{}'.format(added_list), GET)
	res = app.get(url, headers=auth)
	standard_test(res)


	url = testing('/user/{}'.format(userId), GET)
	res = app.get(url)
	standard_test(res)


	'''
	url = testing('/list/{}'.format(str(i)))
	res = app.get(url, status=401)
	res = app.get(url, headers={'Authorization': 'Bearer {}'.format(token)}, status=403)
	'''

	
	url = testing('/list/{}'.format(added_list), DELETE)
	res = app.delete(url, headers=auth)


	url = testing('/user/{}'.format(userId), DELETE)
	res = app.delete(url, headers=auth)


	print('All tests passed!')

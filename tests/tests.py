import sys, os.path
from webtest import TestApp

sys.path.append(os.path.abspath(os.path.join(
	os.path.dirname(__file__),
	os.path.pardir,
	'src')))
from api import app


def testing(url):
	print('Testing {}'.format(url))
	return url

def standard_test(res):
	assert res.content_type == 'application/json'
	assert res.content_length > 0

if __name__ == '__main__':

	app = TestApp(app)


	url = testing('/user/1')
	standard_test(app.get(url))


	url = testing('/user/login')
	res = app.post_json(url, {"email": "test@test.com", "password": "password1"})
	standard_test(res)

	token = res.body
	assert len(token) > 0

	app.post_json(url,
		{"email": "wrong@nowhere.com", "password": "password"},
		status=401)
	
	app.post_json(url,
		{"email": "test@test.com", "password": "wrongpassword"},
		status=401)


	url = testing('/list/new')
	res = app.post_json(url,
		{"title": "Test list", "description": "This is my description"},
		headers={'Authorization': 'Bearer {}'.format(token)})
	
	url = testing('/user/1/lists')
	res = app.get(url)
	standard_test(res)

	lists = res.json
	assert len(lists) > 0


	url = testing('/list/{}'.format(lists[0]))
	res = app.get(url, headers={'Authorization': 'Bearer {}'.format(token)})
	standard_test(res)


	'''
	url = testing('/list/{}'.format(str(i)))
	res = app.get(url, status=401)
	res = app.get(url, headers={'Authorization': 'Bearer {}'.format(token)}, status=403)
	'''


	print('All tests passed!')

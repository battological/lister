Lister
======

Falcon API for a simple list making app.

# Setup

You will need virtualenv and pip:

```
git clone https://github.com/battological/lister.git
cd lister
virtualenv env
source env/bin/activate
pip install -r requirements.txt
cd src
gunicorn api:app
```

# API Specification

> Note: HTTP body must be valid JSON. **bold** fields are required.

## User

| URI | HTTP | JWT | Body | Return | Description |
| --- | ---- | --- | ---- | ------ | ----------- |
| `/user/register` | POST | N | **email**<br>**name**<br>**password** | `{'id': userId}` | Password must be at least 8 characters and contain at least 1 number or symbol. |
| `/user/login` | POST | N | **email**<br>**password** | `{'id': userId, 'jwt': token}` | -- |
| `/user/{userId}` | GET | N | -- | `{'user': userId, 'name': userName}` | -- |
| `/user/{userId}` | PUT | Y | email<br>name<br>password | -- | See above for values of password field. |
| `/user/{userId}` | DELETE | Y | -- | -- | -- |
| `/user/{userId}/lists` | GET | N | -- | `[listId1, ...]` | -- |


## List

| URI | HTTP | JWT | Body | Return | Description |
| --- | ---- | --- | ---- | ------ | ----------- |
| `/list/new` | POST | Y | **title**<br>description<br>public | `{'id': listId}` | The value of "public" may be 0 for private or 1 for public. Lists default to private if this field is ommitted. |
| `/list/{listId}` | GET | Y (if private list) | -- | `{'title': listTitle, 'description': listDescription, 'items': [item1, ...]}` | -- |
| `/list/{listId}` | PUT | Y | title<br>description<br>public | -- | See above for values of public field. |
| `/list/{listId}` | DELETE | Y | -- | -- | -- |

## Item

| URI | HTTP | JWT | Body | Return | Description |
| --- | ---- | --- | ---- | ------ | ----------- |
| `/list/{listId}/add` | POST | Y | **title**<br>description<br>number | `{'id': itemId}` | Number specifies the position of this item in the list. If an item is currently at the specified position, that item (and all lower items) are pushed lower in the list to make room for this item. Number defaults to -1, indicating unspecified position. |
| `/list/{itemId}` | PUT | Y | title<br>description<br>number | -- | See above for values of number field. |
| `/list/{itemId}` | DELETE | Y | -- | -- | -- |

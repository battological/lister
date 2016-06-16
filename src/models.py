import os.path
from datetime import datetime
from peewee import *


db_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
	os.path.pardir,
	'lists.db'))
db = SqliteDatabase(db_path, pragmas=[('foreign_keys', 'ON')])

class BaseModel(Model):
	created=DateTimeField(default=datetime.now)

	class Meta:
		database=db

class User(BaseModel):
	email=CharField(unique=True)
	name=CharField()
	password=CharField()

class List(BaseModel):
	owner=ForeignKeyField(User, related_name='lists', on_delete='CASCADE')
	title=CharField()
	description=CharField(null=True)
	public=IntegerField(default=0) # 0 is private, 1 is public

class Item(BaseModel):
	collection=ForeignKeyField(List, related_name='items', on_delete='CASCADE')
	title=CharField()
	description=CharField(null=True)
	number=IntegerField(default=-1) # -1 is no pref, comes after ordered items

def create_tables():
	db.connect()
	db.create_tables([User, List, Item])

import os.path
from peewee import *


db_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
	os.path.pardir,
	'lists.db'))
db = SqliteDatabase(db_path)

class BaseModel(Model):
	class Meta:
		database = db

class User(BaseModel):
	email = CharField(unique = True)
	name = CharField()
	password = CharField()

class List(BaseModel):
	owner = ForeignKeyField(User, related_name='lists')
	title = CharField()
	description = CharField(null = True)

class Item(BaseModel):
	collection = ForeignKeyField(List, related_name='items')
	title = CharField()
	description = CharField(null = True)

def create_tables():
	db.connect()
	db.create_tables([User, List, Item])

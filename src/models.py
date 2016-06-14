from peewee import *


db = SqliteDatabase('../lists.db')

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

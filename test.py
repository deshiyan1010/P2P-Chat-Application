from peewee import *




db = SqliteDatabase('client.db')

class User(Model):
    uname = TextField()
    publicKey = TextField()
    privateKey = TextField()

    class Meta:
        database = db # This model uses the "people.db" database.

db.connect()

db.create_tables([User])


# u = User(uname='deshiyan',publicKey='efes',privateKey='efesqewfqe')
# u.save()

u = User.select()
print(u[0].uname)
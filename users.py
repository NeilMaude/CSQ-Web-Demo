import hmac                             # hashing functions
import re                               # regular expressions
from google.appengine.ext import db     # GAE data store
from string import letters              # letters function
import random                           # random function library - used to create password salt
import hashlib
from datetime import datetime, timedelta

import parameters       # parameters file for this solution

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(parameters.secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# password creation
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

    @classmethod
    def change_password(cls, name, pw):
        u = User.all().filter('name =', name).get()         # get the user, assumed existing
        if u:
            pw_hash = make_pw_hash(name, pw)
            u.pw_hash = pw_hash                             # this changes the password hash in the object
            return u

# Password retrieval functions
def make_token(length = 30):
    s = ''.join(random.choice(letters[0:52]) for x in xrange(length))
    h = hashlib.sha256(s).hexdigest()
    return s, h
    # return a random string of letters, using only upper and lower characters (no specials), and the hash hexdigest

def get_token_hash(plain_text):
    return hashlib.sha256(plain_text).hexdigest()

def retrieve_password_key(group = 'default'):
    return db.Key.from_path('retrieve_password', group)

class Retrieve_Password(db.Model):
    username = db.StringProperty(required = True)
    token_hash = db.StringProperty(required = True)
    created = db.DateTimeProperty(required = True)

    @classmethod
    def by_hash(cls, token_hash):
        r = Retrieve_Password.all().filter('token_hash =', token_hash).get()
        return r

    @classmethod
    def store_request(cls, username, random_hash):
        return Retrieve_Password(parent = retrieve_password_key(),
                    username = username,
                    token_hash = random_hash,
                    created = datetime.utcnow())

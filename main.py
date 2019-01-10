# This is the main framework code, launching page handlers
# Created 4/5/2014

import webapp2

import pagehandlers

app = webapp2.WSGIApplication([('/?', pagehandlers.phFront),
                               ('/welcome', pagehandlers.phWelcome),
                               ('/faq', pagehandlers.phFAQ),
                               ('/signup', pagehandlers.phSignUp),
                               ('/signin', pagehandlers.phSignIn),
                               ('/tutorial', pagehandlers.phTutorial),
                               ('/feedback', pagehandlers.phFeedback),
                               ('/logout', pagehandlers.phLogout),
                               ('/reportemail', pagehandlers.phReportEmail),
                               ('/retrieve_password', pagehandlers.phRetrievePassword),
                               ('/retrieve_password_sent', pagehandlers.phRetrievePasswordSent),
                               ('/reset_password/?', pagehandlers.phResetPassword),
                               ('/terms', pagehandlers.phTerms),
                               ('/create_tables', pagehandlers.phCSQCreateTables),
                               ('/clear_tables', pagehandlers.phCSQClearTables),
                               ('/send_examples', pagehandlers.phCSQSendExamples),
                               ('/survey/?', pagehandlers.phSurveyLanding),
                               ('/runsurvey/?', pagehandlers.phRunSurvey),
                               ('/surveycomplete/?', pagehandlers.phSurveyComplete),
                               ],
                              debug=True)

# phFront is the application front page - main screen for logged in users, redirect to welcome for not logged in case



# *** Legacy code below here ***


#
#
#
#import logging
#import json
#from datetime import datetime, timedelta



#from google.appengine.api import memcache
#




#def render_str(template, **params):
#    t = jinja_env.get_template(template)
#    return t.render(params)

#def age_set(key, val):
#    save_time = datetime.utcnow()
#    memcache.set(key, (val, save_time))

#def flush_memcache():
#    memcache.flush_all()
    
#def age_get(key):
#    r = memcache.get(key)
#    if r:
#        val, save_time = r
#        age = (datetime.utcnow() - save_time).total_seconds()
#    else:
#        val, age = None, 0

#    return val, age

#def add_post(post):
#    post.put()
#    get_posts(update = True)
#    return str(post.key().id())

#def get_posts(update = False):
#    q = Post.all().order('-created').fetch(limit = 10)
#    mc_key = 'BLOGS'

#    posts, age = age_get(mc_key)
#    if update or posts is None:
#        posts = list(q)
#        age_set(mc_key, posts)

#    return posts, age

#def age_str(age):
#    s = 'Queried %s seconds ago'
#    age = int(age)
#    if age == 1:
#        s = s.replace('seconds', 'second')
#    return s % age
    
#def render_post(response, post):
#    response.out.write('<b>' + post.subject + '</b><br>')
#    response.out.write(post.content)







###### blog stuff

#def blog_key(name = 'default'):
#    return db.Key.from_path('blogs', name)

#class Post(db.Model):
#    subject = db.StringProperty(required = True)
#    content = db.TextProperty(required = True)
#    created = db.DateTimeProperty(auto_now_add = True)
#    last_modified = db.DateTimeProperty(auto_now = True)

#    def render(self):
#        self._render_text = self.content.replace('\n', '<br>')
#        return render_str("post.html", p = self)

#    def as_dict(self):
#        time_fmt = '%c'
#        d = {'subject': self.subject,
#             'content': self.content,
#             'created': self.created.strftime(time_fmt),
#             'last_modified': self.last_modified.strftime(time_fmt)}
#        return d

#class BlogFront(BlogHandler):
#    def get(self):
#        #posts = greetings = Post.all().order('-created')
#        posts, age = get_posts()
#        if self.format == 'html':
#            self.render('front.html', posts = posts, age = age_str(age))
#        else:
#            return self.render_json([p.as_dict() for p in posts])

#class PostPage(BlogHandler):
#    def get(self, post_id):
#        post_key = 'POST_' + post_id

#        post, age = age_get(post_key)
#        if not post:
#            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
#            post = db.get(key)
#            age_set(post_key, post)
#            age = 0

#        if not post:
#            self.error(404)
#            return

#        if self.format == 'html':
#            self.render("permalink.html", post = post, age = age_str(age))
#        else:
#            self.render_json(post.as_dict())

#class NewPost(BlogHandler):
#    def get(self):
#        if self.user:
#            self.render("newpost.html")
#        else:
#            self.redirect("/login")

#    def post(self):
#        if not self.user:
#            self.redirect('/blog')

#        subject = self.request.get('subject')
#        content = self.request.get('content')

#        if subject and content:
#            p = Post(parent = blog_key(), subject = subject, content = content)
#            #p.put()
#            post_id = add_post(p)
#            #posts, age = get_posts(True)
#            #self.redirect('/blog/%s' % str(p.key().id()))
#            self.redirect('/blog/%s' % str(post_id))
#        else:
#            error = "subject and content, please!"
#            self.render("newpost.html", subject=subject, content=content, error=error)


####### Unit 2 HW's
#class Rot13(BlogHandler):
#    def get(self):
#        self.render('rot13-form.html')

#    def post(self):
#        rot13 = ''
#        text = self.request.get('text')
#        if text:
#            rot13 = text.encode('rot13')

#        self.render('rot13-form.html', text = rot13)



#class Signup(BlogHandler):
#    def get(self):
#        self.render("signup-form.html")

#    def post(self):
#        have_error = False
#        self.username = self.request.get('username')
#        self.password = self.request.get('password')
#        self.verify = self.request.get('verify')
#        self.email = self.request.get('email')

#        params = dict(username = self.username,
#                      email = self.email)

#        if not valid_username(self.username):
#            params['error_username'] = "That's not a valid username."
#            have_error = True

#        if not valid_password(self.password):
#            params['error_password'] = "That wasn't a valid password."
#            have_error = True
#        elif self.password != self.verify:
#            params['error_verify'] = "Your passwords didn't match."
#            have_error = True

#        if not valid_email(self.email):
#            params['error_email'] = "That's not a valid email."
#            have_error = True

#        if have_error:
#            self.render('signup-form.html', **params)
#        else:
#            self.done()

#    def done(self, *a, **kw):
#        raise NotImplementedError

#class Unit2Signup(Signup):
#    def done(self):
#        self.redirect('/unit2/welcome?username=' + self.username)

#class Register(Signup):
#    def done(self):
#        #make sure the user doesn't already exist
#        u = User.by_name(self.username)
#        if u:
#            msg = 'That user already exists.'
#            self.render('signup-form.html', error_username = msg)
#        else:
#            u = User.register(self.username, self.password, self.email)
#            u.put()

#            self.login(u)
#            #self.redirect('/blog')
#            self.redirect('/welcome')

#class Login(BlogHandler):
#    def get(self):
#        self.render('login-form.html')

#    def post(self):
#        username = self.request.get('username')
#        password = self.request.get('password')

#        u = User.login(username, password)
#        if u:
#            self.login(u)
#            self.redirect('/blog')
#        else:
#            msg = 'Invalid login'
#            self.render('login-form.html', error = msg)


#class FlushCache(BlogHandler):
#    def get(self):
#        # delete the cache, if it exists
#        flush_memcache()
#        self.redirect('blog')
    
#class Unit3Welcome(BlogHandler):
#    def get(self):
#        if self.user:
#            self.render('welcome.html', username = self.user.name)
#        else:
#            self.redirect('/signup')

#class Welcome(BlogHandler):
#    def get(self):
#        username = self.request.get('username')
#        if valid_username(username):
#            self.render('/unit3/welcome.html', username = username)
#        else:
#            self.redirect('/unit2/signup')

           
#app = webapp2.WSGIApplication([('/?(?:\.json)?', BlogFront),
#                               ('/unit2/rot13', Rot13),
#                               ('/unit2/signup', Unit2Signup),
#                               ('/unit2/welcome', Welcome),
#                               ('/blog/?(?:\.json)?', BlogFront),
#                               ('/blog/([0-9]+)(?:\.json)?', PostPage),
#                               ('/blog/newpost', NewPost),
#                               ('/newpost', NewPost),
#                               ('/signup', Register),
#                               ('/login', Login),
#                               ('/logout', Logout),
#                               ('/unit3/welcome', Unit3Welcome),
#                               ('/welcome', Unit3Welcome),
#                               ('/flush', FlushCache),
#                               ],
#                              debug=True)


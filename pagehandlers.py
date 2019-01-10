# This next part is handler code, which can probably be moved to a class file at some point
# There are also some security functions which should also be a in separate class file
import webapp2
import jinja2
import os
from datetime import datetime, timedelta

template_dir = os.path.join(os.path.dirname(__file__), 'templates')                 # Complains on first run that 'markupsafe' is not present
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

import parameters   # global parameter file
import users        # user account handling for this solution
import mailing      # email handling for this solution

import carnival_data    # data model for carnival demo system

class phPageHandler(webapp2.RequestHandler):
    # Generic page handler class - not called, overloaded by a named class for the page type
    # This page should always show a "work in progress page", if called directly
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    #def render_json(self, d):
    #    json_txt = json.dumps(d)
    #    self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
    #    self.write(json_txt)

    def set_secure_cookie(self, name, val, remember):
        cookie_val = users.make_secure_val(val)
        if remember:
            delta_interval = timedelta(days = 5 * 365.25)                       # persist for 5 years
            s_expiry = (datetime.utcnow() + delta_interval).strftime("%d %B %Y %H:%M:%S") + ' GMT'
            self.response.headers.add_header(
                'Set-Cookie',
                '%s=%s; Path=/; Expires=%s' % (name, cookie_val, s_expiry))     # persist for 5 years
        else:
            self.response.headers.add_header(
                'Set-Cookie',
                '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and users.check_secure_val(cookie_val)

    def login(self, user, remember):
        self.set_secure_cookie('user_id', str(user.key().id()), remember)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and users.User.by_id(int(uid))
        self.format = 'html'
        #if self.request.url.endswith('.json'):
        #    self.format = 'json'
        #else:
        #    self.format = 'html'


class phFront(phPageHandler):
    def get(self):
        if self.user:
            user_name = self.user.name
            self.render('main.html', user_name = user_name)
            #s_ConstructionLogout = '<a href="/logout">' + user_name + '</a>'
        else:
            #user_name = '(Not logged in)'                                  # will eventually redirect to /welcome, once login is complete
            self.redirect('/welcome')
        

class phWelcome(phPageHandler):
    def get(self):
        if self.user:
            self.redirect("/")              # can't use the welcome page if logged in
        else:
            self.render('welcome.html')

# Welcome page needs to check for a logged-in user and redirect to home, if logged in
# Need also a nicer layout

class phFAQ(phPageHandler):
    def get(self):
        self.render('construction.html')

class phTerms(phPageHandler):
    def get(self):
        self.render('construction.html')

# Need a proper template, plus handling of login state in header nav bar

class phSignUp(phPageHandler):
    def get(self):

        # Temporary redirection to / for demonstration purposes...
        self.redirect('/') 

        #if self.user:
        #    self.redirect('/')              # already logged in, can't create a new user here
        #else:
        #    self.render('signup.html')

    def post(self):
         # have 'username', 'email', 'password1', 'password2', 'terms', 'remember-me' fields from the form
        have_error = False
        #self.username = self.request.get('username')
        self.username = self.request.get('email')           # use e-mail as the user name
        self.password = self.request.get('password1')
        self.verify = self.request.get('password2')
        self.email = self.request.get('email')
        self.terms = self.request.get('terms')
        self.remember = self.request.get('remember-me')

        params = dict(username = self.username,
                email_address = self.email,
                error_text = '')

        #if not users.valid_username(self.username):
        #    params['error_text'] = u"That's not a valid username."
        #    have_error = True
        if not users.valid_email(self.email):
            params['error_text'] = "That's not a valid email."
            have_error = True
        elif not users.valid_password(self.password):
            params['error_text'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_text'] = "Your passwords didn't match."
            have_error = True
        elif not self.terms:
            params['error_text'] = "You must accept the terms and conditions in order to use this site."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            #make sure the user doesn't already exist
            u = users.User.by_name(self.username)
            if u:
                self.render('signup.html', error_text = 'A user with that e-mail address already exists.')
            else:
                u = users.User.register(self.username, self.password, self.email)
                u.put()
                if self.remember != '':
                    self.login(u, True)
                else:
                    self.login(u, False)
                mailing.welcome_signup(self.email)      # have now logged-in, send a welcome e-mail
                self.redirect('/')


class phSignIn(phPageHandler):
    def get(self):
        if self.user:
            self.redirect('/')                  # can't sign in again...
        else:
            self.render('signin.html')

    def post(self):
        username = self.request.get('email')
        password = self.request.get('password')
        self.remember = self.request.get('remember-me')

        u = users.User.login(username, password)
        if u:
            if self.remember != '':
                self.login(u, True)
            else:
                self.login(u, False)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('signin.html', error_text = msg)


class phTutorial(phPageHandler):
    def get(self):
        self.render('construction.html')

class phFeedback(phPageHandler):
    def get(self):
        if self.user:
            self.render('construction.html')
        else:
            self.redirect('/welcome')           # if not logged in, can't provide feedback

class phLogout(phPageHandler):
    def get(self):
        self.logout()
        self.redirect('/welcome')               # should this go to the login screen instead?

class phReportEmail(phPageHandler):
    def get(self):
        self.render('construction.html')

class phRetrievePasswordSent(phPageHandler):
    def get(self):
        self.render('/retrieve_password_sent.html')

class phRetrievePassword(phPageHandler):
    def get(self):
        self.render('/retrieve_password.html')

    def post(self):
        user = self.request.get('email')

        # check if the user exists - if not, fail and redirect to this page again (with error text)
        u = users.User.by_name(user)
        if u:
            # found the user - OK to continue
            # create a random string
            # create a hash value of that string
            s, h = users.make_token()
            rp = users.Retrieve_Password.store_request(user, h)     # get a new data object
            rp.put()                                                # save it                
            # send the e-mail to the user, with the original random string
            mailing.send_password_reset(user, s)
            # redirect to the "reminder sent" page
            self.redirect('/retrieve_password_sent')
        else:
            # user doesn't exist
            self.render('retrieve_password.html', error_text = 'There is no user with that e-mail address.')

class phResetPassword(phPageHandler):
    def get(self):
        s = self.request.get('ID')                              # This will hold the random string
        # get the e-mail address from the database, checking that we have a match
        h = users.get_token_hash(s)
        rp = users.Retrieve_Password.by_hash(h)                 # Get back the retrieve password object
        if rp:
            rp_age = (datetime.utcnow() - rp.created).total_seconds()
            if rp_age <= parameters.RESET_PASSWORD_MAX_TIME_SECONDS:
                # OK to record the value in a temp cookie, it can't be forged to change any other user
                self.set_secure_cookie('reset_id', str(s), False)
                self.render('reset_password.html', user_name = rp.username)
            else:
                # delete the record
                rp.delete()
                self.redirect('/retrieve_password')                 # The timelimit has passed
        else:
            self.redirect('/retrieve_password')                 # no valid hash, send them to the retrieve screen

    def post(self):
        have_error = False
        s = self.read_secure_cookie('reset_id')                 # this should already be set
        s_password = self.request.get('password1')
        s_verify = self.request.get('password2')
        
        if s:
            h = users.get_token_hash(s)
            rp = users.Retrieve_Password.by_hash(h)
            if rp:
                rp_age = (datetime.utcnow() - rp.created).total_seconds()
                if rp_age <= parameters.RESET_PASSWORD_MAX_TIME_SECONDS:
                    # have a valid hash, within the time limit
                    # check for any errors, such as mis-matched passwords
                    if not users.valid_password(s_password):
                        s_error = "That wasn't a valid password."
                        have_error = True
                    elif s_password != s_verify:
                        s_error = "Your passwords didn't match."
                        have_error = True        
                    if have_error:
                        self.render('reset_password.html', user_name = rp.username, error_text = s_error)
                    else:
                        # have a valid user and a checked new password
                        # update the user password
                        u = users.User.change_password(rp.username, s_password)
                        u.put()
                        rp.delete()     # can't use this token again
                        #redirect to the login screen
                        #self.render('signin.html', error_text = 'Password changed')
                        self.redirect('/signin')
                else:
                    # delete the record and redirect the user - likely that the timelimit has passed
                    rp.delete()
                    self.redirect('/retrieve_password')
            else:
                self.redirect('/retrieve_password')
        else:
            self.redirect('/retrieve_password')                 # shouldn't ever be possible, but just in case...

# Carnival page handlers here
class phCSQClearTables(phPageHandler):
    def get(self):
        if not self.user:
            self.redirect('/welcome')                           # redirect to welcome page, need to be logged in
        else:
            # we're logged in and it is OK to show this page - remember never to update data on a get() Neil!
            self.render('csq_clear_data.html')

    def post(self):
        # setup the sample structure
        # render error_text value if there is an error
        if carnival_data.clear_database():
            # cleared
            self.render('main.html', user_name = self.user.name, error_text = 'Data structures cleared.')
        else:
            # error
            self.render('main.html', user_name = self.user.name, error_text = 'Failed to clear database.')
       

class phCSQCreateTables(phPageHandler):
    def get(self):
        if not self.user:
            self.redirect('/welcome')                           # redirect to welcome page, need to be logged in
        else:
            # we're logged in and it is OK to show this page - remember never to update data on a get() Neil!
            self.render('csq_setup_data.html')

    def post(self):
        # setup the sample structure
        # render error_text value if there is an error
        t = carnival_data.db_csq_template.by_template_id(1)     # is the default template already there?
        if t:
            # it exists and shouldn't
            error_text = 'Data structures already exist - no need to initialise again.'
            self.render('main.html', user_name = self.user.name, error_text = error_text)
        else:
            # can do the updates
            carnival_data.create_example_csq_list()
            carnival_data.create_example_csq_groups()
            carnival_data.create_example_csq_template()
            self.render('main.html', user_name = self.user.name, error_text = 'Data structures set up and you will not need to do this again.')

class phCSQSendExamples(phPageHandler):
    def get(self):
        # render the form, if we're logged in...
        if not self.user:
            self.redirect('/welcome')                           # redirect to welcome page, need to be logged in
        else:
            # we're logged in and it is OK to show this page - remember never to update data on a get() Neil!
            self.render('csq_send_examples.html')

    def post(self):
        # send 10 example links
        sTo = self.request.get('email')
        if sTo:
            sMessage = """
            Hello,

            A request has been made for the Arena CSQ system to send you some demonstration survey links.  
        
            These links are shown at the end of this message.

            Arena CSQ Team.

            (If you did not expect this e-mail, please disregard it - the Arena CSQ system has not recorded your email address.)
            """
            for i in range(0,10):
                sToken = carnival_data.make_survey_token()       # create a new GUID
                firstname, lastname = carnival_data.make_random_name()

                s = carnival_data.db_csq_survey.store_survey(sToken, firstname, lastname, parameters.MAIL_SENDER_ADDRESS)
                s.put()

                sMessage = sMessage + str(i) + '. ' + parameters.BASE_URL +'/survey?SurveyID=' + sToken + ' (' + firstname + ' ' + lastname + """)
                """ 

            mailing.send_message(sTo, 'Arena CSQ - demonstration survey requests', sMessage)

            self.render('main.html', user_name = self.user.name, error_text = 'Sample questionnaires sent, please check your inbox.')

class phSurveyLanding(phPageHandler):
    def get(self):
        # get the survey ID parameter
        sToken = self.request.get('SurveyID')
        # check it is valid
        s = carnival_data.db_csq_survey.by_survey_id(sToken)
        
        have_error = False
        error_text = None
        if not s:
            have_error = True
            error_text = 'That is not a valid survey ID.'
        else:
            if s.complete:
                have_error = True
                error_text = 'That survey has been completed, you can only do that once.'

        if have_error:
            self.render('csq_survey_landing_invalid.html', error_text = error_text)
        else:
            # we have a valid survey ID and the survey hasn't been completed
            self.render('csq_survey_landing.html', firstname = s.recip_first_name, survey_id = sToken)

class phRunSurvey(phPageHandler):
    def get(self):
        # show the run survey page, for the survey ID
        sToken = self.request.get('SurveyID')
        # check it is valid
        s = carnival_data.db_csq_survey.by_survey_id(sToken)
        
        have_error = False
        error_text = None
        if not s:
            have_error = True
            error_text = 'That is not a valid survey ID.'
        else:
            if s.complete:
                have_error = True
                message_text = 'That survey has already been completed. Thank you for your views, we very much appreciate your time.'

        if have_error:
            self.render('csq_survey_landing_invalid.html', error_text = error_text, message_text = message_text)
        else:
            # got this far, so it is a valid survey
            sGroupID = self.request.get('GroupID')
            if sGroupID:
                nGroupID = int(sGroupID)            # from the URL
            else:
                # try getting it from the database
                nLastGroup = carnival_data.db_csq_lastgroup.by_survey_id(sToken)
                if nLastGroup:
                    nGroupID = nLastGroup.lastgroup_num
                else:
                    nGroupID = 1

            nTemplateID = parameters.DEMO_SURVEY_ID

            # how many groups are there?
            nTotalGroups = carnival_data.get_max_groupid_bytemplateid(nTemplateID)

            # get the group name
            g = carnival_data.db_csq_groups.by_template_and_group_id(nTemplateID, nGroupID)
            if g.count() > 0:
                sGroupName = g[0].group_name

            # get the list of questions for Group #n
            t = carnival_data.db_csq_template.by_templateID_and_groupID(nTemplateID, nGroupID)

            # will need to give some consideration to the responses already provided and their results - lots of db querying here!
            # set up the question objects
            questions = []

            for q in t:
                qn = carnival_data.question(q_name = q.question_num, q_desc = q.question_prompt, q_type = q.question_type)
                if qn.q_type == 'list':
                    # need some list elements here
                    if q.question_list_id:
                        # get the list items 
                        l = carnival_data.db_csq_lists.by_list_id(q.question_list_id)
                        if l:
                            qn.q_list = ['Please choose'] + l.list_value        # this is a list of all the list entries

                if qn.q_type == 'check5':
                    # need to get some labels
                    t_list = ['One','Two','Three','Four','Five']
                    if q.question_list_id:
                        # there is a list in the database
                        l = carnival_data.db_csq_lists.by_list_id(q.question_list_id)
                        if l:
                            qn.q_list = l.list_value        # this is a list of all the list entries
                        else:
                            qn.q_list = t_list
                    else:
                        # there isn't a list, so just use the standard sequence
                        qn.q_list = t_list

                if qn.q_type == 'check4':
                    # need to get some labels
                    t_list = ['One','Two','Three','Four']
                    if q.question_list_id:
                        # there is a list in the database
                        l = carnival_data.db_csq_lists.by_list_id(q.question_list_id)
                        if l:
                            qn.q_list = l.list_value        # this is a list of all the list entries
                        else:
                            qn.q_list = t_list
                    else:
                        # there isn't a list, so just use the standard sequence
                        qn.q_list = t_list

                # now need to look up the question response, if any
                r = carnival_data.db_csq_result.by_survey_id_and_question_num(sToken, q.question_num)
                if r.count() > 0:
                    if r[0].question_value:
                        qn.q_value = r[0].question_value

                questions = questions + [qn]  

            # last section?
            t = carnival_data.db_csq_template.by_templateID_and_groupID(nTemplateID, nGroupID + 1)
            if t.count() > 0:
                # there is one...
                sButtonText = 'Next'
            else:
                # we are on the last page
                sButtonText = 'Finish'

            self.render('csq_survey_run.html', group_number = nGroupID, group_name = sGroupName, questions = questions,
                        next_button_text = sButtonText, num_groups = nTotalGroups)                  # show the CSQ page


    def post(self):
        # post in the values, increment the section (if there are more), redirect
        
        # get the page params - still check that we have a valid GUID and no-one is posting rubbish from another source
        sToken = self.request.get('SurveyID')
        # check it is valid
        s = carnival_data.db_csq_survey.by_survey_id(sToken)
        have_error = False
        error_text = None
        if not s:
            have_error = True
            error_text = 'That is not a valid survey ID.'
        else:
            if s.complete:
                have_error = True
                error_text = 'That survey has been completed - you can only respond once.'

        if have_error:
            self.render('csq_survey_landing_invalid.html', error_text)
        else:
            # got this far, so it is a valid survey
            sGroupID = self.request.get('GroupID')
            if sGroupID:
                nGroupID = int(sGroupID)
            else:
                # try getting it from the database
                nLastGroup = carnival_data.db_csq_lastgroup.by_survey_id(sToken)
                if nLastGroup:
                    nGroupID = nLastGroup.lastgroup_num
                else:
                    nGroupID = 1

            # get the list of questions for Group #n
            nTemplateID = parameters.DEMO_SURVEY_ID
            t = carnival_data.db_csq_template.by_templateID_and_groupID(nTemplateID, nGroupID)

            # save results - lots of db querying here!
            for q in t:
                #qn = carnival_data.question(q_name = q.question_num, q_desc = q.question_prompt, q_type = q.question_type)
                new_value = self.request.get(str(q.question_num))
                #r = carnival_data.db_csq_result.add_update_result(sToken, q.question_num, new_value)
                #r.put()
                r = carnival_data.db_csq_result.get_result(sToken, q.question_num)
                if r:
                    if r.count() == 0:
                        # no result
                        r = carnival_data.db_csq_result.store_result(sToken, q.question_num, new_value)
                        r.put()
                    else:
                        r[0].delete()
                        r = carnival_data.db_csq_result.store_result(sToken, q.question_num, new_value)
                        r.put()
                        
            if self.request.get('formButton') == 'Next':
                nNewGroupID = nGroupID + 1
            else:
                # Back button
                if nGroupID > 1:
                    nNewGroupID = nGroupID - 1

            # last section?
            t = carnival_data.db_csq_template.by_templateID_and_groupID(nTemplateID, nNewGroupID)
            if t.count() > 0:
                # there is one...
                lg = carnival_data.db_csq_lastgroup.by_survey_id(sToken)
                if lg:
                    lg.lastgroup_num = nNewGroupID
                    lg.put()
                else:
                    lg = carnival_data.db_csq_lastgroup.store_lastgroup(sToken, nNewGroupID)
                    lg.put()
                    #if lg.count() == 0:
                    #    # no result
                    #    lg = carnival_data.db_csq_result.store_lastgroup(sToken, nNewGroupID)
                    #    lg.put()
                    #else:
                    #    lg[0].delete()
                    #    lg = carnival_data.db_csq_result.store_lastgroup(sToken, nNewGroupID)
                    #    lg.put()

                self.redirect('/runsurvey?SurveyID=' + sToken + ';GroupID=' + str(nNewGroupID))
            else:
                # we have completed the survey now...
                s = carnival_data.db_csq_survey.by_survey_id(sToken)
                if s:
                    s.complete = True
                    s.put()
                self.redirect('/surveycomplete?SurveyID=' + sToken)

class phSurveyComplete(phPageHandler):
    def get(self):
        # get the survey ID parameter
        sToken = self.request.get('SurveyID')
        # check it is valid
        s = carnival_data.db_csq_survey.by_survey_id(sToken)
        
        have_error = False
        error_text = None
        if not s:
            have_error = True
            error_text = 'That is not a valid survey ID.'
        else:
            if not s.complete:
                have_error = True
                error_text = 'That survey has not yet been completed.'

        if have_error:
            self.render('csq_survey_landing_invalid.html', error_text = error_text)
        else:
            # we have a valid survey ID and the survey hasn't been completed
            self.render('csq_survey_complete.html', firstname = s.recip_first_name, survey_id = sToken)
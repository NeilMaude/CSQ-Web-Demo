from google.appengine.ext import db     # GAE data store
import parameters       # parameters file for this solution
from string import letters              # letters function
import random                           # random function library - used to create GUIDs

# CSQ List Handling (drop down lists for questions)
def csq_lists_key(group = 'default'):
    return db.Key.from_path('csq_lists', group)

class db_csq_lists(db.Model):
    list_id = db.IntegerProperty(required = True)
    list_value = db.StringListProperty(required = True)             # Note that this is one db record for an entire list!

    @classmethod
    def store_list(cls, new_list_id, new_list):
        return db_csq_lists(parent = csq_lists_key(),
                    list_id = new_list_id,
                    list_value = new_list)
    
    @classmethod                                                    # Return the list matching the list_id
    def by_list_id(cls, list_id):
        l = db_csq_lists.all().filter('list_id = ', list_id).get()
        return l

# CSQ question groups
def csq_groups_key(group = 'default'):
    return db.Key.from_path('csq_groups', group)

class db_csq_groups(db.Model):
    template_id = db.IntegerProperty(required = True)
    group_id = db.IntegerProperty(required = True)
    group_name = db.StringProperty(required = True)             # Note that this is a db record for the group title

    @classmethod
    def store_group(cls, new_template_id, new_group_id, new_group_name):
        return db_csq_groups(parent = csq_groups_key(),
                    template_id = new_template_id,
                    group_id = new_group_id,
                    group_name = new_group_name)
    
    @classmethod                                                # Return the group matching the group_id
    def by_template_and_group_id(cls, template_id, group_id):
        g = db_csq_groups.all()
        g.filter('template_id = ', template_id)
        g.filter('group_id = ', group_id)
        g.get()
        return g

def get_max_groupid_bytemplateid(t_id):
    q = db.GqlQuery("SELECT group_id FROM db_csq_groups WHERE template_id = " + str(t_id) + " ORDER BY group_id DESC")
    results = q.fetch(1000)
    if results:
        return results[0].group_id

# Questionnaire template ID functions
def csq_template_key(group = 'default'):
    return db.Key.from_path('csq_template', group)

class db_csq_template(db.Model):
    template_id = db.IntegerProperty(required = True)
    question_num = db.IntegerProperty(required = True)            
    question_type = db.StringProperty(required = True)
    question_group = db.IntegerProperty(required = True)
    question_prompt = db.StringProperty(required = True)
    question_list_id = db.IntegerProperty()

    @classmethod
    def store_template_item(cls, new_template_id, new_question_num, new_question_type, new_question_group,
                            new_question_prompt, new_question_list_id = None):
        return db_csq_template(parent = csq_template_key(),
                    template_id = new_template_id,
                    question_num = new_question_num,
                    question_type = new_question_type,
                    question_group = new_question_group,
                    question_prompt = new_question_prompt,
                    question_list_id = new_question_list_id)
    
    @classmethod                                                # Return the group matching the group_id
    def by_template_id(cls, template_id):
        t = db_csq_template.all().filter('template_id = ', template_id).get()
        return t

    @classmethod
    def by_templateID_and_groupID(cls, t_id, g_id):               # return the items matching survey and group IDs 
        s = db_csq_template.all()
        s.filter('template_id = ', t_id)
        s.filter('question_group = ', g_id)
        s.order('question_num')
        s.get()
        return s

# Survey data object - a survey assigned to a passenger
def csq_survey_key(group = 'default'):
    return db.Key.from_path('csq_survey', group)

class db_csq_survey(db.Model):
    survey_id = db.StringProperty(required = True)              # will be a GUID generated by the system
    recip_first_name = db.StringProperty(required = True)       # recipient name     
    recip_last_name = db.StringProperty(required = True)   
    recip_email = db.StringProperty()                           # recipient e-mail address.  For demo, this will always be the same
    complete = db.BooleanProperty()                             # flag to show complete - these are one-time only

    @classmethod
    def store_survey(cls, new_survey_id, new_recip_first_name, new_recip_last_name, new_recip_email = None, new_complete = False):
        return db_csq_survey(parent = csq_survey_key(),
                    survey_id = new_survey_id,
                    recip_first_name = new_recip_first_name,
                    recip_last_name = new_recip_last_name,
                    recip_email = new_recip_email,
                    complete = new_complete)
    
    @classmethod                                                # Return the survey items matching the survey_id
    def by_survey_id(cls, survey_id):
        s = db_csq_survey.all().filter('survey_id = ', survey_id).get()
        return s

# Make a new survey GUID - should check that it doesn't exist, just in case of random collisions, but don't bother for a demo
def make_survey_token(length = 30):
    s = ''.join(random.choice(letters[0:52]) for x in xrange(length))
    return s
    # return a random string of letters, using only upper and lower characters

def make_random_name():
    # random names generator
    firstnames = ['Andrew', 'Bernard', 'Charles', 'David', 'Edward', 'Fred', 'George', 'Harry', 'Ian', 'John', 
                  'Keith', 'Liam', 'Matthew', 'Neil', 'Oliver', 'Peter', 'Quintin', 'Robert',  'Stephen', 'Tim', 
                  'Victor', 'William', 'Xavier']
    lastnames = ['Andrews', 'Brown', 'Croft', 'Davidson', 'Edwards', 'Fitzpatrick', 'Geoffrey', 'Hudson', 'Ingle', 'Jameson',
                 'Knight', 'Light', 'Matthews', 'Nolan', 'Osgerby', 'Peters', 'Quatermass', 'Robertson', 'Stephens', 'Thompson',
                 'Underwood', 'Vincenzo', 'Walters', 'Xavier', 'Young', 'Zuchorski']
    return random.choice(firstnames), random.choice(lastnames)

# question class, used for passing values into the CSQ display form
class question(object):
    def __init__(self, q_name=None, q_desc = None, q_type = None, q_value = None, q_list = None):
        self.q_name = q_name
        self.q_desc = q_desc
        self.q_type = q_type
        self.q_value = q_value
        self.q_list = q_list

# results class - storing the values for each survey and question
def csq_result_key(group = 'default'):                                  # surely some bug previously, when this was left as 'survey key'..?
    return db.Key.from_path('csq_result', group)

class db_csq_result(db.Model):
    survey_id = db.StringProperty(required = True)              # will be a GUID generated by the system
    question_num = db.IntegerProperty(required = True)
    question_value = db.TextProperty()                         # always storing results as a string, can be empty

    @classmethod
    def store_result(cls, new_survey_id, new_question_num, new_question_value = False):
        return db_csq_result(parent = csq_result_key(),
                    survey_id = new_survey_id,
                    question_num = new_question_num,
                    question_value = new_question_value)

    @classmethod                                                # Return the survey items matching the survey_id
    def by_survey_id_and_question_num(cls, survey_id, question_num):
        r = db_csq_result.all()
        r.filter('survey_id = ', survey_id)
        r.filter('question_num = ', question_num)
        r.get()
        return r

    @classmethod
    def add_update_result(cls, s_id, q_num, q_val):
        r = db_csq_result.all()
        r.filter('survey_id = ', s_id)
        r.filter('question_num = ', q_num)
        r.get()
        if r.count() == 0:
            # no existing value, create one
            r = cls.store_result(s_id, q_num, q_val)
            return r
        else:
            r[0].question_value = q_val     # just update the first one!
            return r[0]

    @classmethod
    def get_result(cls, s_id, q_num):
        r = db_csq_result.all()
        r.filter('survey_id = ', s_id)
        r.filter('question_num = ', q_num)
        r.get()
        return r

def create_example_csq_list():                                      # Set up the sample lists
    ''' Create a sample CSQ list, with some default entries '''
    sample_list = ['One', 'Two', 'Three']
    sample_list_id = 1
    l = db_csq_lists.store_list(sample_list_id, sample_list)
    l.put()
    ''' Create the restaurants list '''
    restaurant_list = ['Adriatic', 'Ligurian']
    l = db_csq_lists.store_list(2, restaurant_list)
    l.put()
    ''' Restaurant sittings list '''
    l = db_csq_lists.store_list(3, ['1st sitting', '2nd sitting', 'Freedom'])
    l.put()
    ''' Questionnaire on behalf of '''
    l = db_csq_lists.store_list(4, ['Just yourself', 'Yourself and one other', 'Yourself and two others', 'Yourself and 3 others', 'Yourself and 4 or more others'])
    l.put()
    ''' Question K1 & 2 list - how many times with P&O before'''
    before_list = ['Never', 'Once', 'Twice', 'Three times', 'Four or more times']
    l = db_csq_lists.store_list(5, before_list)
    l.put()
    companies_list = ['Thomson Cruises', 'Carnival Cruises', 'Celebrity Cruises', 'Costa Cruises', 'Cunard Line', 'Fred Olsen',
                      'Holland America', 'Island Cruises', 'NCL', 'Ocean Village', 'Princess Cruises', 'Royal Caribbean', 'Saga',
                      'Other']
    l = db_csq_lists.store_list(6, companies_list)
    l.put()
    check4_list = ['Excellent', 'Good', 'Fair', 'Poor']
    l = db_csq_lists.store_list(7, check4_list)
    l.put()
    check5_list = check4_list + ['Not used']
    l = db_csq_lists.store_list(8, check5_list)
    l.put()
    again_list = ['Unlikely', 'Within 1 year', 'Within 1-2 years', 'Within 2-3 years', 'Within 3+ years']
    l = db_csq_lists.store_list(9, again_list)
    l.put()
    where_list = ['Western Mediterranean', 'Eastern Mediterranean', 'Caribbean', 'Canary Islands', 'Baltic or Fjords', 'Rest of the world']
    l = db_csq_lists.store_list(10, where_list)
    l.put()
    ship_list = ['Adonia', 'Arcadia', 'Aurora', 'Azura', 'Britannia', 'Oceana', 'Oriana', 'Ventura']
    l = db_csq_lists.store_list(11, ship_list)
    l.put()

def create_example_csq_groups():                                # Just create a couple of sample groups
    ''' Create sample CSQ groups, with some default entries '''
    g = db_csq_groups.store_group(1, 1, 'Your Cruise Details')
    g.put()
    g = db_csq_groups.store_group(1, 2, 'Your Overall Cruise Experience')
    g.put()
    g = db_csq_groups.store_group(1, 3, 'Pre-Cruise')
    g.put()
    g = db_csq_groups.store_group(1, 4, 'Previous Cruise Experience')
    g.put()
    g = db_csq_groups.store_group(1, 5, 'Future Intentions')
    g.put()

def create_example_csq_template():                                # Just create some sample questions in those groups above
    ''' Create sample template with some test questions '''
    q = db_csq_template.store_template_item(1,1,'list',1,'Which restaurant did you choose?', 2)
    q.put()
    q = db_csq_template.store_template_item(1,2,'list',1,'Which dinner sitting did you choose?', 3)
    q.put()
    q = db_csq_template.store_template_item(1,3,'list',1,'On behalf of how many people are you completing this questionnaire?',4)
    q.put()
    q = db_csq_template.store_template_item(1,4,'check4',2,'Overall enjoyment of the cruise',7)
    q.put()
    q = db_csq_template.store_template_item(1,5,'check4',2,'Overall comfort and presentation of your cabin',7)
    q.put()
    q = db_csq_template.store_template_item(1,6,'check4',2,'Overal enjoyment of the food',7)
    q.put()
    q = db_csq_template.store_template_item(1,7,'check4',2,'Overall enjoyment of the entertainment',7)
    q.put()
    q = db_csq_template.store_template_item(1,8,'check4',2,'Overall quality of service',7)
    q.put()
    q = db_csq_template.store_template_item(1,9,'check4',2,'Overall friendliness and approachability of the staff',7)
    q.put()
    q = db_csq_template.store_template_item(1,10,'check4',2,'Value for money of your cruise',7)
    q.put()
    q = db_csq_template.store_template_item(1,11,'check4',2,'Weather conditions',7)
    q.put()
    q = db_csq_template.store_template_item(1,12,'text',2,'Your comments')
    q.put()
    # Pre-Cruise section, group 3
    q = db_csq_template.store_template_item(1,13,'check5',3,'Quality of service offered by our reservation staff',8)
    q.put()
    q = db_csq_template.store_template_item(1,14,'check5',3,'Ease of booking shore excursions pre-cruise',8)
    q.put()
    q = db_csq_template.store_template_item(1,15,'check5',3,'Quality of information on Cruise Personalisation',8)
    q.put()
    q = db_csq_template.store_template_item(1,16,'check5',3,'Efficiency of the check-in process',8)
    q.put()
    q = db_csq_template.store_template_item(1,17,'check5',3,'Quality of any flights booked through P&O Cruises',8)
    q.put()
    q = db_csq_template.store_template_item(1,18,'text',3,'Your comments')
    q.put()
    # Previous cruise experience, group 4
    q = db_csq_template.store_template_item(1,19,'list',4,'How many times, if at all, have you cruised with P&O Cruises before?',5)
    q.put()
    q = db_csq_template.store_template_item(1,20,'list',4,'How many times, if at all, have you cruised with another company?',5)
    q.put()
    q = db_csq_template.store_template_item(1,21,'list',4,'If you have cruised with a company other than P&O Cruises, which company did you cruise with last?',6)
    q.put()
    # Future intentions, group 5
    q = db_csq_template.store_template_item(1,22,'list',5,'How likely are you to cruise with P&O Cruises again?',9)
    q.put()
    q = db_csq_template.store_template_item(1,23,'list',5,'Where would you like to cruise to next?',10)
    q.put()
    q = db_csq_template.store_template_item(1,24,'list',5,'Which ship are you most likely to take your next P&O Cruises holiday on?',11)
    q.put()

def clear_table(table_name):
    q = db.GqlQuery("SELECT * FROM " + table_name)
    results = q.fetch(1000)
    while results:
        db.delete(results)
        results = q.fetch(1000, len(results))
    return True

def clear_database():
    ''' Clear out the database tables, all except users '''
    #lists
    #groups
    #template questions
    have_error = False
    if not clear_table('db_csq_result'):
        have_error = True

    if not clear_table('db_csq_lists'):
        have_error = True

    if not clear_table('db_csq_groups'):
        have_error = True

    if not clear_table('db_csq_survey'):
        have_error = True

    if not clear_table('db_csq_template'):
        have_error = True

    return (not have_error)

# last group or page class - storing the values for each survey respondent
def csq_lastgroup_key(group = 'default'):                                  
    return db.Key.from_path('csq_lastgroup', group)

class db_csq_lastgroup(db.Model):
    survey_id = db.StringProperty(required = True)              # will be a GUID generated by the system
    lastgroup_num = db.IntegerProperty(required = True)

    @classmethod
    def store_lastgroup(cls, new_survey_id, new_lastgroup_num):
        return db_csq_lastgroup(parent = csq_lastgroup_key(),
                    survey_id = new_survey_id,
                    lastgroup_num = new_lastgroup_num)

    @classmethod                                                # Return the item matching the survey_id
    def by_survey_id(cls, survey_id):
        r = db_csq_lastgroup.all().filter('survey_id = ', survey_id).get()
        return r

    #@classmethod
    #def add_update_lastgroup(cls, new_survey_id, new_lastgroup_num):
    #    r = db_csq_lastgroup.all()
    #    r.filter('survey_id = ', new_survey_id)
    #    r.get()
    #    if r.count() == 0:
    #        # no existing value, create one
    #        r = cls.store_lastgroup(new_survey_id, new_lastgroup_num)
    #        return r
    #    else:
    #        r.lastgroup_num = new_lastgroup_num     # just update the first one!
    #        return 
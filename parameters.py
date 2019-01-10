# Security parameters
secret = 'somesecretterm'       # Secret used for password hashing functions
                                #This definitely needs to be abstracted to a production parameter file!!
RESET_PASSWORD_MAX_TIME_SECONDS = 60 * 60   # An hour - 60 secs * 60 mins

# Development/debug parameters
ENV_PRODUCTION = True           # This is the production evnironment - set to False if specifically don't want be the production site
ENV_DEVELOPMENT = False         # This is the development environment - set to False if don't want to be this site
ENV_TEST = False                # This is the test environment - set to False if not testing
                                # *OBVIOUSLY* should only be one of these at once when the site has been released!

#BASE_URL = 'http://axiomatic-fiber-549.appspot.com'   # base url of site - surely this will be useful at some point
#BASE_URL = 'http://localhost:8080'
BASE_URL = 'http://carnival-demo.appspot.com'


NO_MAIL = False                 # Set to True to stop sending any e-mails
MAIL_SENDER_ADDRESS = 'neil.maude@gmail.com'        # Need to change that before production!
MAIL_SENDER_NAME = 'No reply'                     # Need to change that before production!
MAIL_SENDER_ADDRESS_DEBUG = 'neil.maude@gmail.com'
MAIL_SENDER_NAME_DEBUG = 'Neil Maude'

# Carnival parameters
DEMO_SURVEY_ID = 1  



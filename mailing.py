# Anything to do with sending mail goes in here
import parameters 

from google.appengine.api import mail

def send_message(to, subject, message, sender = None):    
    if not sender:
        # no sender, so boilerplate one
        if parameters.ENV_DEVELOPMENT:
            # always set to default and over-write the 'to'
            sender = parameters.MAIL_SENDER_NAME_DEBUG + ' <' + parameters.MAIL_SENDER_ADDRESS_DEBUG + '>'
            sendto = sender
            message = """(Redirected in site development mode, was: """ + to + """)
            """ + message
        else:
            # use the production parameters
            sender = parameters.MAIL_SENDER_NAME + ' <' + parameters.MAIL_SENDER_ADDRESS + '>'
            sendto = to
    msg = mail.EmailMessage(sender = sender)
    msg.subject = subject
    msg.to = sendto
    msg.body = message
    return msg.send()

def welcome_signup(recip_email):
    """ Send a 'welcome to the system' e-mail """
    s_message = """
    Hello,

    Welcome to Arena CSQ!

    You've just completed your sign-up process.

    We hope you like the site.

    Arena CSQ Team.

    (If this wasn't you and someone else has used your e-mail address,
    please report it via the link below and we'll do our best to sort it.

    """
    s_message = s_message + parameters.BASE_URL + '/reportemail)'
    s_subject = 'Welcome to Arena CSQ'
    return send_message(to = recip_email, subject = s_subject, message = s_message)

def send_password_reset(recip_email, s_random):
    """ Send a password reset e-mail """
    s_message = """
    Hello,

    Arena CSQ has been asked to send you a link to reset your password.

    Please click on the link below to reset your password.

    Arena CSQ Team.

    (If this wasn't you and someone else has used your e-mail address,
    you can ignore the e-mail.  No-one can reset your account without
    the unique key in this link.)

    """
    s_message = s_message + parameters.BASE_URL + '/reset_password?ID=' + s_random
    s_subject = 'Request to reset Arena CSQ password'
    return send_message(to = recip_email, subject = s_subject, message = s_message)
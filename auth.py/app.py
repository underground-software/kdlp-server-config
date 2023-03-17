from urllib.parse import parse_qs
from html import escape
from http import cookies
import sys, datetime, bcrypt, sqlite3, hashlib, random

VERSION="0.1"

FORM_LOGIN="""
	<form id="login" method="post" action="/login">
		<label for="username">Username:<br /></label>
		<input name="username" type="text" id="username" />
	<br />
		<label for="password">Password:<br /></label>
		<input name="password" type="password" id="password" />
	<br />
		<button type="submit">Submit</button>
	</form>
"""

FORM_LOGOUT="""
	<div class="logout_left">
	<table>
	<tr>
		<th>Cookie Key</th>
		<th>Value</th>
	</tr>
	<tr>
		
		<td>Token</td>
		<td>%(token)s</td>
	</tr>
	<tr>
		
		<td>Username</td>
		<td>%(username)s</td>
	</tr>
	<tr>
		
		<td>Expiry</td>
		<td>%(expiry)s</td>
	</tr>
	<tr>
		
		<td>Remaining</td>
		<td>%(remaining)s</td>
	</tr>
	</table>
	</div>

	<div class="logout_right">
	<a href="/login/index.md">Authorizied Home</a>
	<br />
	<a href="/login/second.md">Authorizied Second Page</a>
	</div>

	<form id="logout" method="post" action="/login/logout.md">
		<button type="submit">Logout</button>
	</form>
"""	

# Source: https://stackoverflow.com/questions/14107260/set-a-cookie-and-retrieve-it-with-python-and-wsgi
def set_cookie_header(name, value, days=0, minutes=15):
    dt = datetime.datetime.now() + datetime.timedelta(days=days,minutes=minutes)
    fdt = dt.strftime('%a, %d %b %Y %H:%M:%S GMT')
    #secs = days * 86400
    secs = 60 * 15
    return ('Set-Cookie', '{}={}; Expires={}; Max-Age={}; Path=/'.format(name, value, fdt, secs))


def printd(string):
	return print(string, file=sys.stderr)

# shortand for bytes(string, "UTF-8")
def bytes8(string):
	return bytes(string, "UTF-8")

# shortand for str(string, "UTF-8")
def str8(string):
	return str(string, "UTF-8")

def do_sqlite3_comm(db, comm, commit=False, fetch=False):
	result=None
	db_con = sqlite3.connect(db)
	db_cur0 = db_con.cursor()
	
	printd("RUN SQL: %s" % comm)
	db_cur1 = db_cur0.execute(comm)

	if fetch:
		result=db_cur1.fetchone()
		printd("SQL RES: %s" % str(result))

	if commit:
		printd("RUN SQL: COMMIT;")
		db_cur2 = db_cur1.execute("COMMIT;")

	db_con.close()

	return result


KDLP_SESSIONS_DB='sessions.db'
KDLP_USERS_DB = 'users.db'
KDLP_URLBASE='/var/www/html/kdlp.underground.software/'

def session_enum():
	session_enum.cnt += 1
	return session_enum.cnt
session_enum.cnt = 0

# data = (token,..)
SESSION_GET_TOKEN=session_enum()
SESSION_GET_TOKEN_COMM="SELECT token, user, expiry FROM sessions WHERE token = \"%s\";"

# data = (...,user,...)
SESSION_GET_USER=session_enum()
SESSION_GET_USER_COMM="SELECT token, user, expiry FROM sessions WHERE user= \"%s\";"

# data = (token, user, expiry)
SESSION_NEW=session_enum()
SESSION_NEW_COMM="INSERT INTO sessions (token, user, expiry) VALUES (\"%s\", \"%s\", \"%s\");"

# data = (token,..)
SESSION_DROP_TOKEN=session_enum()
SESSION_DROP_TOKEN_COMM = "DELETE FROM sessions WHERE token = \"%s\";"

# data = (...,user,...)
SESSION_DROP_USER=session_enum()
SESSION_DROP_USER_COMM = "DELETE FROM sessions WHERE user = \"%s\";"

def _do_sessions_comm(comm, commit=False, fetch=False):
	return do_sqlite3_comm(KDLP_SESSIONS_DB, comm, commit=commit, fetch=fetch)

def do_sessions_comm(comm, data=None):
	if   comm == SESSION_NEW:
		return _do_sessions_comm(SESSION_NEW_COMM % data, commit=True)
	elif comm == SESSION_GET_TOKEN:
		return _do_sessions_comm(SESSION_GET_TOKEN_COMM % (data[0]), fetch=True)
	elif comm == SESSION_GET_USER:
		return _do_sessions_comm(SESSION_GET_USER_COMM % (data[1]), fetch=True)
	elif comm == SESSION_DROP_TOKEN:
		return _do_sessions_comm(SESSION_DROP_TOKEN_COMM % (data[0]), commit=True)
	elif comm == SESSION_DROP_USER:
		return _do_sessions_comm(SESSION_DROP_USER_COMM % (data[1]), commit=True)
	else:
		printd("unknown sessions comm type")

def new_session_by_username(session_username):
	
	if get_session_by_username(session_username) is not None:
		return None

	# Make a session_token out of sha256(username + time + random string)
	session_token = hashlib.sha256(bytes8(session_username \
		+ str(datetime.datetime.now())) \
		+ bytes8(''.join(random.choices("ABCDEFGHIJ",k=10)))).hexdigest()

	# sessions expire in 15 minutes for now
	session_expiry = (datetime.datetime.utcnow() + datetime.timedelta(minutes=15)).timestamp()

	do_sessions_comm(SESSION_NEW, (session_token, session_username, session_expiry))

	return get_session_by_username(session_username)

def drop_session_by_username(session_username):
	do_sessions_comm(SESSION_DROP_USER, (None, session_username, None))
	return

def drop_session_by_token(session_token):
	do_sessions_comm(SESSION_DROP_TOKEN, (session_token, None, None))
	return

def get_session_by_username(session_username):
	session = do_sessions_comm(SESSION_GET_USER, (None, session_username, None))
	if session is None:
		return None	

	session_expiry = session[2]
	
	# if the current timestamp is greater than session expiry,
	# purge the old session from the databse and return none 
	# by re-trying the request
	if datetime.datetime.utcnow().timestamp() > session_expiry:
		drop_session_by_username(session_username)
		return get_session_by_username(session_username)

	return session

# return none if token is expired and also purge old entry
def get_session_by_token(session_token):
	session = do_sessions_comm(SESSION_GET_TOKEN,(session_token, None, None))
	if session is None:
		return None	

	session_expiry = session[2]

	# if the current timestamp is greater than session expiry,
	# purge the old session from the databse and return none 
	# by re-trying the request
	if datetime.datetime.utcnow().timestamp() > session_expiry:
		drop_session_by_token(session_token)
		return get_session_by_token(session_token)
	return session

	
def ok_html_docs_headers(document, extra_docs, extra_headers, start_response):
	start_response('200 OK', [('Content-Type', 'text/html')] + extra_headers)
	return [bytes8(document)] + [bytes8(d) for d in extra_docs]

def ok_text(text, start_response):
	start_response('200 OK', [('Content-Type', 'text/plain')])
	return [bytes8(text)]


def ok_urlencoded(content, start_response):
	start_response('200 OK', [('Content-Type', 'application/x-www-form-urlencoded')])
	return [bytes8(content)]

def unauth_urlencoed(content, start_response):
	start_response('401 Unauthorized', [('Content-Type', \
		'application/x-www-form-urlencoded')])
	return [bytes8(content)]

def notfound_urlencoded(content, start_response):
	start_response('404 Not Found', [('Content-Type', \
		'application/x-www-form-urlencoded')])
	return [bytes8(content)]
	
def _handle_check(token, start_response):
	session = get_session_by_token(token)

	# If we have an unexpired session, the bearer
	# of the token is authenticated as session[1]
	if session is not None:
		return ok_urlencoded('auth=%s' % session[1], start_response)
	else:
		return unauth_urlencoded('auth=nil', start_response)

def handle_check(queries, start_response):
	token = queries.get('token',[''])[0]
	if len(token) > 0:
		return _handle_check(token, start_response)
	else:
		return ok_urlencoded('error="No token= supplied in URL. Nothing done."', start_response)

def _handle_logout(username, start_response):
	session = get_session_by_username(username)

	# see comment in handle_check()
	if session is not None:
		drop_session_by_username(username)
		return ok_urlencoded('logout=%s' % username, start_response)
	else:
		return notfound_urlencoded('logout=nil', start_response)

def handle_logout(queries, start_response):
	username = queries.get('username',[''])[0]
	if len(username) > 0:
		return _handle_logout(username, start_response)
	else:
		return ok_urlencoded('error="No username= suplied in URL. Nothing done."', start_response)

def get_req_body_size(env):
	try:
		req_body_size = int(env.get('CONTENT_LENGTH', 0))
	except ValueError:
		req_body_size = 0
	
	return req_body_size

def is_post_req(env):
	return get_req_body_size(env) > 0


def get_pwdhash_by_user(username):
	comm="select pwdhash from users where username = \"%s\";" % username

	result=do_sqlite3_comm(KDLP_USERS_DB, comm, fetch=True)
	if result is not None:
		result = result[0]

	return result

CREDS_OK	=0
CREDS_CONFLICT	=1
CREDS_BAD	=2
def check_creds_from_body(env):
	session=None
	username=''
	status = CREDS_BAD
	req_body_size= get_req_body_size(env)

	if (req_body_size > 0):
		req_body = env['wsgi.input'].read(req_body_size) 
		data = parse_qs(req_body)

		# get actual urlencoded body content
		username = escape(str8(data.get(bytes8('username'), [b''])[0]))
		password = escape(str8(data.get(bytes8('password'), [b''])[0]))

		# plaintext password immediately checked and only used here
		pwdhash=get_pwdhash_by_user(username)
		if pwdhash is not None and bcrypt.checkpw(bytes8(password), bytes8(pwdhash)):
			# if the password is valid,
			# try to start a new session right away
			session = new_session_by_username(username)
			# session for $username already exists if we still get None
			status = CREDS_CONFLICT if session is None else CREDS_OK

	if status == CREDS_CONFLICT:
		session = ('',username,'')

	return [session, status]

def get_session_from_cookie(env):
	user_session=None

	# get auth=$TOKEN from user cookie
	cookie_user_raw = env.get('HTTP_COOKIE', '')
	
	cookie_user = cookies.BaseCookie('')
	
	cookie_user.load(cookie_user_raw)

	auth = cookie_user.get('auth', cookies.Morsel())
	if auth.value is not None:
		user_session = get_session_by_token(auth.value)

	return user_session	

def generate_page_login(form, start_response, extra_headers, msg):
	base=''

	with open(KDLP_URLBASE + 'header', "r") as f:
		base += f.read()

	with open(KDLP_URLBASE + 'nav', "r") as f:
		base += f.read()

	def dump_line():
		return '<br /><hr /><br >'

	def dump_as_str(name, var):
		return "<code>%s = %s</code><br />" % (name, str(var))

	base += form 
	extra = [dump_line(), dump_as_str("message", msg),
		dump_as_str("auth.py", VERSION), dump_line()]

	return ok_html_docs_headers(base, extra, extra_headers, start_response)
		
def handle_login(env, start_response):
	msg='welcome, please login'

	# check if user $TOKEN valid and authenticate as $USERNAME
	user_session = get_session_from_cookie(env)
	if user_session is not None:
		msg = 'you are logged in as %s' % user_session[1]
	
	# if not already logged in from cookie and if posting credentials
	login_status=None
	if user_session is None and is_post_req(env):
		# attempt to login using credentials from body
		[user_session, login_status] = check_creds_from_body(env)
	

	# put cookie in here to set user cookie
	extra_headers = []
	# we made an attemmpt to login, handle the login response
	if login_status is not None:
		if login_status == CREDS_BAD:
			msg = 'incorrect login'
		elif login_status == CREDS_CONFLICT:
			msg = 'existing open session for user %s' % user_session[1]
			# user_session only contains the username when creds conflict
			# to create this message. Now we clear it to normalize logic
			user_session=None
		elif login_status == CREDS_OK:
			msg = 'start new session for user %s' % user_session[1]
			# we just logged in as $USERNAMAE
			extra_headers.append(set_cookie_header("auth", user_session[0]))
	
	
	# default to login form unless we have a valid user_session
	main_form = FORM_LOGIN
	if user_session is not None:
		expiry_dt = datetime.datetime.fromtimestamp(user_session[2])
		main_form = FORM_LOGOUT  % {
			'token' : user_session[0],
			'username' : user_session[1],
			'expiry' : expiry_dt.strftime('%a, %d %b %Y %H:%M:%S GMT'),
			'remaining' : str(expiry_dt - datetime.datetime.utcnow())
		}

	return generate_page_login(main_form, start_response, extra_headers, msg)


def application(env, start_response):

	path_info = env.get("PATH_INFO", "")
	query_string = env.get("QUERY_STRING", "")
	queries = parse_qs(query_string)

	printd("New request: path_info=\"%s\", queries=\"%s\"" \
		% (str(path_info), str(queries)))

	if path_info == "/login":
		return handle_login(env, start_response)
	elif path_info == "/check":
		return handle_check(queries, start_response)
	elif path_info == "/logout":
		return handle_logout(queries, start_response)
	else:
		return notfound_urlencoded('error="Page not found."', start_response)

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

KDLP_SESSIONS_DB='sessions.db'
KDLP_USERS_DB = 'users.db'
KDLP_URLBASE='/var/www/html/kdlp.underground.software/'

# Source: https://stackoverflow.com/questions/14107260/set-a-cookie-and-retrieve-it-with-python-and-wsgi
def set_cookie_header(name, value, days=0, minutes=15):
    dt = datetime.datetime.now() + datetime.timedelta(days=days,minutes=minutes)
    fdt = dt.strftime('%a, %d %b %Y %H:%M:%S GMT')
    #secs = days * 86400
    secs = 60 * 15
    return ('Set-Cookie', '{}={}; Expires={}; Max-Age={}; Path=/'.format(name, value, fdt, secs))

# shortand for bytes(string, "UTF-8")
def bytes8(string):
	return bytes(string, "UTF-8")

# shortand for str(string, "UTF-8")
def str8(string):
	return str(string, "UTF-8")

def new_session_by_username(session_username):
	
	if get_session_by_username(session_username) is not None:
		return None

	# Make a session_token out of sha256(username + time + random string)
	session_token = hashlib.sha256(bytes8(session_username \
		+ str(datetime.datetime.now())) \
		+ bytes8(''.join(random.choices("ABCDEFGHIJ",k=10)))).hexdigest()

	# sessions expire in 15 minutes for now
	session_expiry = (datetime.datetime.utcnow() + datetime.timedelta(minutes=15)).timestamp()

	db = sqlite3.connect(KDLP_SESSIONS_DB)
	db_cur = db.cursor()
	db_comm = "INSERT INTO sessions (token, user, expiry) VALUES (\"%s\", \"%s\", \"%s\");" % \
		(session_token, session_username, session_expiry)
	
	print("RUN SQL: %s" % db_comm, file=sys.stderr)
	res = db_cur.execute(db_comm)

	res.execute("COMMIT;")
	
	db.close()

	return get_session_by_username(session_username)

def drop_session_by_username(session_username):
	db = sqlite3.connect(KDLP_SESSIONS_DB)
	db_cur = db.cursor()
	db_comm = "DELETE FROM sessions WHERE user = \"%s\";" % session_username
	
	print("RUN SQL: %s" % db_comm, file=sys.stderr)
	res = db_cur.execute(db_comm)

	res.execute("COMMIT;")

	db.close()
	return

def drop_session_by_token(session_token):
	db = sqlite3.connect(KDLP_SESSIONS_DB)
	db_cur = db.cursor()
	db_comm = "DELETE FROM sessions WHERE token = \"%s\";" % session_token
	
	print("RUN SQL: %s" % db_comm, file=sys.stderr)
	res = db_cur.execute(db_comm)

	res.execute("COMMIT;")

	db.close()
	return

def _get_session_by_username(session_username):
	db = sqlite3.connect(KDLP_SESSIONS_DB)
	db_cur = db.cursor()
	db_comm = "SELECT token, user, expiry FROM sessions WHERE user = \"%s\";" % session_username
	

	print("RUN SQL: %s" % db_comm, file=sys.stderr)
	res = db_cur.execute(db_comm)
	results = res.fetchone()

	print("_get_by_username(%s)=%s" % (session_username, results), file=sys.stderr)

	db.close()

	return results

def get_session_by_username(session_username):
	session = _get_session_by_username(session_username)
	if session is None:
		return None	


	nowunix = datetime.datetime.utcnow().timestamp()
	session_expiry = session[2]

	expired = nowunix > session_expiry

	print("get_by_username(%s)=%s, now=%s, expiry=%s, expired=%d" % (session_username, session, nowunix, session_expiry, expired), file=sys.stderr)

	if expired:
		drop_session_by_username(session_username)
		return get_session_by_username(session_username)

	return session

def _get_session_by_token(session_token):
	db = sqlite3.connect(KDLP_SESSIONS_DB)
	db_cur = db.cursor()
	db_comm = "SELECT token, user, expiry FROM sessions WHERE token = \"%s\";" % session_token

	print("RUN SQL: %s" % db_comm, file=sys.stderr)
	res = db_cur.execute(db_comm)
	results = res.fetchone()

	print("_get_by_token(%s)=%s" % (session_token, results), file=sys.stderr)

	db.close()

	return results

# return none if token is expired and also purge old entry
def get_session_by_token(session_token):
	session = _get_session_by_token(session_token)
	if session is None:
		return None	

	nowunix = datetime.datetime.utcnow().timestamp()
	session_expiry = session[2]

	expired = nowunix > session_expiry

	print("get_by_token(%s)=%s, now=%s, expiry=%s, expired=%d" % \
		(session_token, session, nowunix, session_expiry, expired), \
		file=sys.stderr)

	if expired:
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
	
def handle_check(token, start_response):
	session = get_session_by_token(token)

	# If we have an unexpired session, the bearer
	# of the token is authenticated as session[1]
	if session is not None:
		return ok_urlencoded('auth=%s' % session[1], start_response)
	else:
		return unauth_urlencoded('auth=nil', start_response)

def handle_logout(username, start_response):
	session = get_session_by_username(username)

	# see comment in handle_check()
	if session is not None:
		drop_session_by_username(username)
		return ok_urlencoded('logout=%s' % username, start_response)
	else:
		return notfound_urlencoded('logout=nil', start_response)

def get_req_body_size(env):
	try:
		req_body_size = int(env.get('CONTENT_LENGTH', 0))
	except ValueError:
		req_body_size = 0
	
	return req_body_size

def is_post_req(env):
	return get_req_body_size(env) > 0


def get_pwdhash_by_user(username):
	db = sqlite3.connect(KDLP_USERS_DB)
	db_cur = db.cursor()

	res = db_cur.execute("select pwdhash from users where username = \"%s\";" % username)

	res_content = res.fetchone()
	if res_content is not None:
		res_content = res_content[0]
	db.close()

	return res_content

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

		username = escape(str8(data.get(bytes8('username'), [b''])[0]))
		password = escape(str8(data.get(bytes8('password'), [b''])[0]))

		pwdhash=get_pwdhash_by_user(username)
		if pwdhash is not None and bcrypt.checkpw(bytes8(password), bytes8(pwdhash)):
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

	# save pat info and query string
	path_info = env.get("PATH_INFO", "")
	query_string = env.get("QUERY_STRING", "")
	queries = parse_qs(query_string)

	# branch based on path
	if path_info == "/":
		# / which is not used right now
		return ok_text("login home", start_response)
	if path_info == "/login":
		# path content is below
		return handle_login(env, start_response)
	elif path_info == "/check":
		token = queries.get('token',[''])[0]
		if len(token) > 0:
			return handle_check(token, start_response)
		else:
			return ok_urlencoded('error="No token= supplied in URL. Nothing done."', start_response)
	elif path_info == "/logout":
		username = queries.get('username',[''])[0]
		if len(username) > 0:
			return handle_logout(username, start_response)
		else:
			return ok_urlencoded('error="No username= suplied in URL. Nothing done."', start_response)
	else:
		return notfound_urlencoded('error="Page not found."', start_response)

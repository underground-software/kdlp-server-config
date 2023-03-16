from urllib.parse import parse_qs
from html import escape
from http import cookies
import sys, datetime, bcrypt, sqlite3, hashlib
import random

form="""
	<form id="login" method="post" action="/login">
		<label for="username">Username:<br /></label>
		<input name="username" type="text" id="username" />
	<br />
		<label for="password">Password:<br /></label>
		<input name="password" type="password" id="password" />
	<br />
		<button type="submit">Submit</button>
	</form>

	<br />
	<table>
	<tr>
		<th>Key</th>
		<th>Value</th>
	</tr>
	<tr>
		
		<td>Content Length</td>
		<td>%(length)d</td>
	</tr>
	<tr>
		<td>Input</td>
		<td>%(input)s</td>
	</tr>
	<tr>
		<td>Username</td>
		<td>%(user)s</td>
	</tr>
	<tr>
		<td>Password</td>
		<td>%(pass)s</td>
	<tr>
		<td>Password Hash</td>
		<td>%(pwdhash)s</td>
	</tr>
	</tr>
	</table>
"""

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

def new_session_token(session_username):
	
	if get_session_by_username(session_username) is not None:
		return None

	# Make a session_token out of sha256(username + time + random string)
	session_token = hashlib.sha256(bytes8(session_username + str(datetime.datetime.now())) \
		+ bytes8(''.join(random.choices("ABCDEFGHIJ",k=10)))).hexdigest()

	KDLP_SESSIONS_DB='sessions.db'

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

	return session_token

def drop_session_by_username(session_username):
	KDLP_SESSIONS_DB='sessions.db'
	db = sqlite3.connect(KDLP_SESSIONS_DB)
	db_cur = db.cursor()
	db_comm = "DELETE FROM sessions WHERE user = \"%s\";" % session_username
	
	print("RUN SQL: %s" % db_comm, file=sys.stderr)
	res = db_cur.execute(db_comm)

	res.execute("COMMIT;")

	db.close()
	return

def get_session_by_username(session_username):
	KDLP_SESSIONS_DB='sessions.db'
	db = sqlite3.connect(KDLP_SESSIONS_DB)
	db_cur = db.cursor()
	db_comm = "SELECT token, user, expiry FROM sessions WHERE user = \"%s\";" % session_username
	

	print("RUN SQL: %s" % db_comm, file=sys.stderr)
	res = db_cur.execute(db_comm)
	results = res.fetchone()

	print("get_by_username(%s)=%s" % (session_username, results), file=sys.stderr)

	db.close()

	return results

def _get_session_by_token(session_token):
	KDLP_SESSIONS_DB='sessions.db'
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

	print("get_by_token(%s)=%s, now=%s" % (session_token, session, nowunix), file=sys.stderr)

	return session

def application(env, start_response):
	base=''
	msg=''
	urlbase='/var/www/html/kdlp.underground.software/'

	path_info = env.get("PATH_INFO", "")
	print("path_info = %s" % str(path_info), file=sys.stderr)

	query_string = env.get("QUERY_STRING", "")
	queries = parse_qs(query_string)
	print("query_string = %s" % str(query_string), file=sys.stderr)
	if len(path_info) > 0:
		if path_info == "/login":
			msg = 'on login page'
		elif path_info == "/check":
			token = queries.get('token',[''])[0]
			#start_response('200 Ok', [('Content-Type', 'text/plain')])
			start_response('200 OK', [('Content-Type', 'application/x-www-form-urlencoded')])
			if len(token) > 0:
				session = get_session_by_token(token)
				# If we have an unexpired session, the bearer
				# of the token is authenticated
				if session is not None:
					return [bytes8('auth=%s' % session[1])]
				else:
					return [bytes8('auth=nil')]
			else:
				return [b'no token given']

			return [b'test content']
		elif path_info == "/logout":
			username = queries.get('username',[''])[0]
			start_response('200 OK', [('Content-Type', 'application/x-www-form-urlencoded')])
			if len(username) > 0:
				session = get_session_by_username(username)
				if session is not None:
					drop_session_by_username(username)
					return [bytes8('logout=%s' % username)]
				else:
					return [bytes8('logout=nil')]
			else:
				return [b'no username given']
				
		else:
			start_response('404 Not Found', [('Content-Type', 'text/plain')])
			return [b'not found']
			msg = 'on another page: [%s]' % str(path_info)		
			
		

	with open(urlbase + 'header', "r") as f:
		base += f.read()

	with open(urlbase + 'nav', "r") as f:
		base += f.read()
	
	#base += '<h1>Hello, world!</h1>'

	try:
		req_body_size = int(env.get('CONTENT_LENGTH', 0))
	except ValueError:
		req_body_size = 0

	if (req_body_size > 0):
		req_body = env['wsgi.input'].read(req_body_size) 
		data = parse_qs(req_body)
		username = escape(str8(data.get(bytes8('username'), [b''])[0]))
		password = escape(str8(data.get(bytes8('password'), [b''])[0]))
	
	else:
		req_body = b""
		data = {}
		username = ""
		password = ""

	pwdhash=b''
	if len(password) > 0:
		pwdhash = bcrypt.hashpw(bytes8(password), bcrypt.gensalt())
	base += form % {
		'length' : req_body_size,
		'input' : str8(req_body),
		'user' : username,
		'pass' : password,
		'pwdhash' : str8(pwdhash)
	}
	
	KDLP_USERS_DB = 'users.db'
	# if the body is not empty, we are getting a post request, check the password
	match = False
	if req_body_size > 0:
		db = sqlite3.connect(KDLP_USERS_DB)
		db_cur = db.cursor()
		res = db_cur.execute("select pwdhash from users where username = \"%s\"" % username)
		res_content = res.fetchone()
		if res_content is not None:
			saved_hash = res_content[0]
			print("%s saved_hash = %s" % (username, str(saved_hash)), file=sys.stderr)
			match = bcrypt.checkpw(bytes8(password), bytes8(saved_hash))
		db.close()

	# get cookie
	cookie_user_raw = env.get('HTTP_COOKIE', '')
	
	cookie_user = cookies.BaseCookie('')
	
	cookie_user.load(cookie_user_raw)
	
	auth = cookie_user.get('auth',cookies.Morsel())
	
	print("raw: %s" % str(cookie_user_raw), file=sys.stderr)
	print("cookie: %s" % str(auth.value), file=sys.stderr)

	cookie_header = (None, None)
	cookie_content = cookie_header[1]
	if match == True:
		session_token = new_session_token(username)
		# only set the new token cookie if there isnt an active session
		if session_token is not None:
			print("starting new session for %s" % (username,), file=sys.stderr)
			cookie_header = set_cookie_header("auth", session_token)
			cookie_content = cookie_header[1]
			start_response('200 OK', [('Content-Type', 'text/html'), cookie_header])
		else:
			print("not starting conflicting session for %s" % \
				(username), file=sys.stderr)
			start_response('200 OK', [('Content-Type', 'text/html')])
	else:
		start_response('200 OK', [('Content-Type', 'text/html')])


	def dump_as_str(name, var):
		return b"<br /><hr /><br /><code>%s = %s</code><br />" % \
			(bytes8(name), bytes8(str(var)))

	return [bytes8(base),
		dump_as_str("msg", msg),
		dump_as_str("match", match),
		dump_as_str("cookie-set", cookie_content),
		dump_as_str("cookie-received", cookie_user),
		dump_as_str("env", env),
	b"<br /><hr />"]

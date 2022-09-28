# Should trigger codeql/python/ql/src/Security/CWE-022/TarSlip.ql
# faulty code from CodeQL bad code sample
import tarfile, os.path

def open_tar():
  with tarfile.open('archive.zip') as tar:
    #BAD : This could write any file on the filesystem.
    for entry in tar:
      tar.extract(entry, "/tmp/unpack/")

urlpatterns = [
    # Route to user_picture
    url(r'^user-pic1$', user_picture1, name='user-picture1'),
    url(r'^user-pic2$', user_picture2, name='user-picture2'),
    url(r'^user-pic3$', user_picture3, name='user-picture3')
]

# should trigger codeql/python/ql/src/Security/CWE-022/PathInjection.ql twice
def user_picture1(request):
    """A view that is vulnerable to malicious file access."""
    filename = request.GET.get('p')
    # BAD: This could read any file on the file system
    data = open(filename, 'rb').read()
    return HttpResponse(data)

def user_picture2(request):
    """A view that is vulnerable to malicious file access."""
    base_path = '/server/static/images'
    filename = request.GET.get('p')
    # BAD: This could still read any file on the file system
    data = open(os.path.join(base_path, filename), 'rb').read()
    return HttpResponse(data)

  import socket, ldap, re
# should trigger codeql/python/ql/src/Security/CVE-2018-1281/BindToAllInterfaces.ql twice
# binds to all interfaces, insecure
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 31137))

# binds to all interfaces, insecure
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', 4040))


# should trigger codeql/python/ql/src/Security/CWE-020-ExternalAPIs/UntrustedDataToExternalAPI.ql
from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/xss")
def xss():
    username = request.args.get("username")
    return make_response("Hello {}".format(username))
  
# This should trigger codeql/python/ql/src/Security/CWE-078/CommandInjection.ql

urlpatterns = [
    # Route to command_execution
    url(r'^command-ex1$', command_execution_unsafe, name='command-execution-unsafe'),
    url(r'^command-ex2$', command_execution_safe, name='command-execution-safe')
]

COMMANDS = {
    "list" :"ls",
    "stat" : "stat"
}

def command_execution_unsafe(request):
    if request.method == 'POST':
        action = request.POST.get('action', '')
        #BAD -- No sanitizing of input
        subprocess.call(["application", action])
        
# Should trigger codeql/python/ql/src/Security/CWE-079/ReflectedXss.ql 
from flask import escape

app = Flask(__name__)

@app.route('/unsafe')
def unsafe():
    first_name = request.args.get('name', '')
    return make_response("Your name is " + first_name)
  
# should trigger codeql/python/ql/src/Security/CWE-089/SqlInjection.ql
  
from django.conf.urls import url
from django.db import connection

def show_user(request, username):
    with connection.cursor() as cursor:
        # BAD -- Using string formatting
        cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
        user = cursor.fetchone()

        # BAD -- Manually quoting placeholder (%s)
        cursor.execute("SELECT * FROM users WHERE username = '%s'", username)
        user = cursor.fetchone()

urlpatterns = [url(r'^users/(?P<username>[^/]+)$', show_user)]

# should trigger codeql/python/ql/src/Security/CWE-090/LdapInjection.ql

@app.route("/normal")
def normal():
    unsafe_dc = request.args['dc']
    unsafe_filter = request.args['username']

    dn = "dc={}".format(unsafe_dc)
    search_filter = "(user={})".format(unsafe_filter)

    ldap_connection = ldap.initialize("ldap://127.0.0.1")
    user = ldap_connection.search_s(
        dn, ldap.SCOPE_SUBTREE, search_filter)
    
    
 # should trigger codeql/python/ql/src/Security/CWE-094/CodeInjection.ql
urlpatterns = [
    # Route to code_execution
    url(r'^code-ex1$', code_execution_bad, name='code-execution-bad'),
    url(r'^code-ex2$', code_execution_good, name='code-execution-good')
]

def code_execution(request):
    if request.method == 'POST':
        first_name = base64.decodestring(request.POST.get('first_name', ''))
        #BAD -- Allow user to define code to be run.
        exec("setname('%s')" % first_name)

# should trigger codeql/python/ql/src/Security/CWE-116/BadTagFilter.ql

def filterScriptTags(content): 
    oldContent = ""
    while oldContent != content:
        oldContent = content
        content = re.sub(r'<script.*?>.*?</script>', '', content, flags= re.DOTALL | re.IGNORECASE)
    return content
 


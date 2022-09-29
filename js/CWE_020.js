// should trigger codeql/javascript/ql/src/Security/CWE-020/IncompleteHostnameRegExp.ql

app.get('/some/path', function(req, res) {
    let url = req.param('url'),
        host = urlLib.parse(url).host;
    // BAD: the host of `url` may be controlled by an attacker
    let regex = /^((www|beta).)?example.com/;
    if (host.match(regex)) {
        res.redirect(url);
    }
});

// should trigger codeql/javascript/ql/src/Security/CWE-020/IncompleteUrlSchemeCheck.ql

function sanitizeUrl(url) {
    let u = decodeURI(url).trim().toLowerCase();
    if (u.startsWith("javascript:"))
        return "about:blank";
    return url;
}

// should trigger codeql/javascript/ql/src/Security/CWE-020/IncompleteUrlSubstringSanitization.ql or codeql/javascript/ql/src/Security/CWE-020/IncompleteUrlSubstringSanitizationSpecific.ql

app.get('/some/path', function(req, res) {
    let url = req.param("url");
    // BAD: the host of `url` may be controlled by an attacker
    if (url.includes("example.com")) {
        res.redirect(url);
    }
});

// should trigger the above two alerts

app.get('/some/path', function(req, res) {
    let url = req.param("url"),
        host = urlLib.parse(url).host;
    // BAD: the host of `url` may be controlled by an attacker
    if (host.includes("example.com")) {
        res.redirect(url);
    }
});

// should trigger codeql/javascript/ql/src/Security/CWE-020/IncorrectSuffixCheck.ql

function endsWith(x, y) {
  return x.lastIndexOf(y) === x.length - y.length;
}
// should trigger codeql/javascript/ql/src/Security/CWE-020/MissingOriginCheck.ql

function postMessageHandler(event) {
    let origin = event.origin.toLowerCase();

    console.log(origin)
    // BAD: the origin property is not checked
    eval(event.data);
}

window.addEventListener('message', postMessageHandler, false);
// should trigger codeql/javascript/ql/src/Security/CWE-020/MissingRegExpAnchor.ql

app.get("/some/path", function(req, res) {
    let url = req.param("url");
    // BAD: the host of `url` may be controlled by an attacker
    if (url.match(/https?:\/\/www\.example\.com\//)) {
        res.redirect(url);
    }
});

// should trigger codeql/javascript/ql/src/Security/CWE-020/UselessRegExpCharacterEscape.ql

let regex = new RegExp('(^\s*)my-marker(\s*$)'),
    isMyMarkerText = regex.test(text);


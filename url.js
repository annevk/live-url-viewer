function Url(input, base) {
  try {
    if (base) base = UrlParser.parse(base);

    if (/^[\u0009\u000A\u000C\u000D\u0020]|[\u0009\u000A\u000C\u000D\u0020]$/.test(input)) {
      this._exception = "invalid leading/trailing whitespace characters";
      input = input.replace(/^[\u0009\u000A\u000C\u000D\u0020]+/, "");
      input = input.replace(/[\u0009\u000A\u000C\u000D\u0020]+$/, "")
    };

    var url = UrlParser.parse(input, {base: base});
    this._scheme = null;
    this._scheme_data = null;
    this._username = "";
    this._password = null;
    this._host = null;
    this._port = "";
    this._path = [];
    this._query = null;
    this._fragment = null;

    for (var property in url) {
      this["_" + property] = url[property]
    }
  } catch (e) {
    this._href = input;
    this._exception = e.message
  }
};

Url.BASE_ENCODE_SET = "([\\uD800-\\uDBFF][\\uDC00-\\uDFFF])|[^\\u0020-\\u007E]";
Url.SIMPLE_ENCODE_SET = new RegExp(Url.BASE_ENCODE_SET, "g");
Url.PASSWORD_ENCODE_SET = new RegExp(Url.BASE_ENCODE_SET + "|[\\@/]", "g");
Url.USERNAME_ENCODE_SET = new RegExp(Url.BASE_ENCODE_SET + "|[\\@/:]", "g");
Url.DEFAULT_ENCODE_SET = new RegExp(Url.BASE_ENCODE_SET + "|[\\u0020\"#<>?]", "g");
Url.QUERY_ENCODE_SET = new RegExp(Url.BASE_ENCODE_SET + "|[\\x20\\x23\\x3C\\x3E\\x60]", "g");

Url.DEFAULT_PORT = {
  ftp: "21",
  file: null,
  gopher: "70",
  http: "80",
  https: "443",
  ws: "80",
  wss: "443"
};

Url.RELATIVE_SCHEME = Object.keys(Url.DEFAULT_PORT);
Url.URL_CODE_POINTS = new RegExp("[a-zA-Z0-9!$&'()*+,\\-./:;=?@_~\\u00A0-\\uD7FF\\uE000-\\uFDCF\\uFDF0-\\uFFFD\\uD800-\\uDFFF]");

Url.utf8PercentEncode = function(codepoint) {
  var enc = null;
  var c1 = codepoint.charCodeAt(0);

  if (c1 < 128) {
    enc = [c1]
  } else if (c1 > 127 && c1 < 2048) {
    enc = [(c1 >> 6) | 192, (c1 & 63) | 128]
  } else if ((c1 & 63488) != 55296) {
    enc = [(c1 >> 12) | 224, ((c1 >> 6) & 63) | 128, (c1 & 63) | 128]
  } else {
    var c2 = codepoint.charCodeAt(1);

    if ((c1 & 64512) != 55296 || (c2 & 64512) != 56320) {
      enc = [(c1 >> 12) | 224, ((c1 >> 6) & 63) | 128, (c1 & 63) | 128]
    } else {
      c1 = ((c1 & 1023) << 10) + (c2 & 1023) + 65536;

      enc = [
        (c1 >> 18) | 240,
        ((c1 >> 12) & 63) | 128,
        ((c1 >> 6) & 63) | 128,
        (c1 & 63) | 128
      ]
    }
  };

  var result = "";

  if (enc != null) {
    for (var i = 0; i < enc.length; i++) {
      result += "%" + (Math.floor(enc[i] / 16)).toString(16) + (enc[i] % 16).toString(16)
    }
  };

  return result.toUpperCase()
};

Url.percentDecode = function(input) {
  var warn = null;

  if (/%($|[^0-9a-fA-F]|.$|.[^0-9a-fA-F])/.test(input)) {
    warn = "Percent sign (\"%\") not followed by two hexadecimal digits"
  };

  var result = input.replace(/%[0-9a-fA-F]{2}/g, function(c) {
    return String.fromCharCode(parseInt(c.slice(1, c.length), 16))
  });

  if (warn) {
    result = new String(result);
    result.exception = warn
  };

  return result
};

Url.utf8PercentDecode = function(input) {
  return input.replace(/(%[0-9a-fA-F]{2})+/g, function(chars) {
    var bytes = [];

    for (var i = 0; i < chars.length; i += 3) {
      bytes.push(parseInt(chars.slice(i + 1, i + 2 + 1), 16))
    };

    chars = "";

    while (bytes.length > 0) {
      if (bytes[0] < 128) {
        chars += String.fromCharCode(bytes.shift())
      } else if (bytes[0] < 194) {
        chars += "%" + bytes.shift().toString(16).toUpperCase()
      } else if (bytes[0] < 224) {
        if (bytes.length == 1) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else if ((bytes[1] & 192) != 128) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else {
          chars += String.fromCharCode((bytes.shift() << 6) + bytes.shift() - 12416)
        }
      } else if (bytes[0] < 240) {
        if (bytes.length <= 2) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else if ((bytes[1] & 192) != 128) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else if ((bytes[1] & 192) != 128) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else if (bytes[0] == 224 && bytes[1] < 160) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else if ((bytes[2] & 192) != 128) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else {
          chars += String.fromCharCode(
            (bytes.shift() << 12) + (bytes.shift() << 6) + bytes.shift() - 925824
          )
        }
      } else if (bytes[0] < 245) {
        if (bytes.length <= 3) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else if ((bytes[1] & 192) != 128) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else if (bytes[0] == 240 && bytes[1] < 144) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else if (bytes[0] == 244 && bytes[1] >= 144) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else if ((bytes[2] & 192) != 128) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else if ((bytes[3] & 192) != 128) {
          chars += "%" + bytes.shift().toString(16).toUpperCase()
        } else {
          chars += String.fromCharCode(
            (bytes.shift() << 18) + (bytes.shift() << 12) + (bytes.shift() << 6) + bytes.shift() - 63447168
          )
        }
      } else {
        chars += "%" + bytes.shift().toString(16).toUpperCase()
      }
    };

    return chars
  })
};

Url.percentEncode = function(string, encodeSet) {
  return string.replace(encodeSet, function(codePoint) {
    return Url.utf8PercentEncode(codePoint)
  })
};

Url.pathConcat = function(base, path) {
  base = (base ? base.slice(0) : []);

  if (path[0] == ".") {
    path.shift();
    base.pop()
  };

  if (path.length == 1 && path[0] == "") {
    path = base
  } else if (path.length > 1 && path[0] == "") {
    path.shift()
  } else {
    base.pop();
    path = base.concat(path)
  };

  return path
};

Url.prototype = {
  hostParser: function(input, unicodeFlag) {
    if (typeof unicodeFlag === 'undefined') unicodeFlag = null;
    if (input == "") throw new Failure("empty host");

    if (input.substring(0, 1) == "[") {
      if (input.slice(-1) != "]") {
        this._parse_error = true;
        throw new Failure("unmatched brackets in host")
      };

      return new IPAddr(input.slice(1, input.length - 1))
    };

    var domain = percentDecode(input.encode(Encoding.UTF_8)).encode(Encoding.UTF_8);

    try {
      var uri = new Addressable.URI;
      uri.host = domain;
      var asciiDomain = uri.normalizedHost
    } catch (e) {
      throw new Failure("invalid domain - " + e)
    };

    if (asciiDomain.chars.some(function(c) {
      return "\u0000\t\n #%/:?@[\\]".indexOf(c) != -1
    })) {
      throw new Failure("invalid domain - reserved characters")
    };

    if (unicodeFlag) {
      return asciiDomain
    } else {
      return asciiDomain
    }
  },

  hostSerializer: function(host) {
    if (host == null) return "";
    return host
  }
};

Url.canonicalizeIpv6 = function(pre, post, ipv4) {
  if (typeof ipv4 === 'undefined') ipv4 = null;
  if (typeof post === 'undefined') post = [];
  var slots = (ipv4 ? 6 : 8);

  while (pre.length + post.length < slots) {
    pre.push("0")
  };

  pre = pre.concat(post);

  pre.splice.apply(pre, [0, pre.length].concat(pre.map(function(n) {
    return parseInt(n, 16).toString(16).toUpperCase()
  })));

  var zero = null;

  for (var i = 0; i <= slots - 2; i++) {
    if (pre[i] == "0" && pre[i] == "0") {
      zero = i;
      break
    }
  };

  if (!zero) {
    post = null
  } else {
    post = pre.slice(zero + 1, pre.length);
    pre = pre.slice(0, zero);

    while (post.length > 1 && post[0] == "0") {
      post.shift()
    };

    if (ipv4 && post.length == 1 && post[0] == "0") post = null
  };

  var result = pre.join(":");
  if (post) result += "::" + post.join(":");
  if (ipv4) result += "::" + ipv4;
  return result
};

Object.defineProperties(Url.prototype, {
  scheme: {
    enumerable: true,
    configurable: true,

    get: function() {
      return this._scheme
    },

    set: function(scheme) {
      this._scheme = scheme
    }
  },

  schemeData: {
    enumerable: true,
    configurable: true,

    get: function() {
      return this._schemeData
    },

    set: function(schemeData) {
      this._schemeData = schemeData
    }
  },

  host: {
    enumerable: true,
    configurable: true,

    get: function() {
      return this._host
    },

    set: function(host) {
      this._host = host
    }
  },

  path: {
    enumerable: true,
    configurable: true,

    get: function() {
      return this._path
    },

    set: function(path) {
      this._path = path
    }
  },

  query: {
    enumerable: true,
    configurable: true,

    get: function() {
      return this._query
    },

    set: function(query) {
      this._query = query
    }
  },

  fragment: {
    enumerable: true,
    configurable: true,

    get: function() {
      return this._fragment
    },

    set: function(fragment) {
      this._fragment = fragment
    }
  },

  exception: {
    enumerable: true,
    configurable: true,

    get: function() {
      return this._exception
    },

    set: function(exception) {
      this._exception = exception
    }
  }
});

Url.prototype.serializer = function(excludeFragment) {
  if (typeof excludeFragment === 'undefined') excludeFragment = false;
  var output = this._scheme + ":";

  if (!this._scheme_data) {
    output += "//";

    if (this._username != "" || this._password != null) {
      output += this._username || "";
      if (this._password != null) output += ":" + this._password;
      output += "@"
    };

    output += this.hostSerializer(this._host);
    if (this._port.length != 0) output += ":" + this._port;
    output += "/" + this._path.join("/")
  } else {
    output += this._scheme_data
  };

  if (this._query != null) output += "?" + this._query;

  if (this._fragment != null && !excludeFragment) {
    output += "#" + this._fragment
  };

  return output
};

Object.defineProperties(Url.prototype, {
  href: {
    enumerable: true,
    configurable: true,

    get: function() {
      return this._href || this.serializer()
    },

    set: function(value) {
      try {
        var oldhref = this._href;
        var oldexception = this._exception;
        Url.apply(this, [value, null])
      } finally {
        this._href = oldhref;
        this._exception = oldexception
      }
    }
  },

  protocol: {
    enumerable: true,
    configurable: true,

    get: function() {
      return (this._scheme ? this._scheme + ":" : ":")
    },

    set: function(value) {
      try {
        UrlParser.parse(value, {url: this, startRule: "setProtocol"})
      } catch (e) {
        this.exception = e.message
      }
    }
  },

  username: {
    enumerable: true,
    configurable: true,

    get: function() {
      return (this._username ? this._username : "")
    },

    set: function(value) {
      try {
        UrlParser.parse(value, {url: this, startRule: "setUsername"})
      } catch (e) {
        this.exception = e.message
      }
    }
  },

  password: {
    enumerable: true,
    configurable: true,

    get: function() {
      return (this._password ? this._password : "")
    },

    set: function(value) {
      try {
        UrlParser.parse(value, {url: this, startRule: "setPassword"})
      } catch (e) {
        this.exception = e.message
      }
    }
  },

  host: {
    enumerable: true,
    configurable: true,

    get: function() {
      return this.hostname + ":" + this.port
    },

    set: function(value) {
      try {
        UrlParser.parse(value, {url: this, startRule: "setHost"})
      } catch (e) {
        this.exception = e.message
      }
    }
  },

  hostname: {
    enumerable: true,
    configurable: true,

    get: function() {
      return this.hostSerializer(this._host)
    },

    set: function(value) {
      try {
        UrlParser.parse(value, {url: this, startRule: "setHostname"})
      } catch (e) {
        this.exception = e.message
      }
    }
  },

  port: {
    enumerable: true,
    configurable: true,

    get: function() {
      return (this._port ? this._port : "")
    },

    set: function(value) {
      try {
        UrlParser.parse(value.toString(), {url: this, startRule: "setPort"})
      } catch (e) {
        this.exception = e.message
      }
    }
  },

  pathname: {
    enumerable: true,
    configurable: true,

    get: function() {
      if (!this._scheme) return "";
      return this._scheme_data || ("/" + this._path.join("/"))
    },

    set: function(value) {
      try {
        UrlParser.parse(value.toString(), {url: this, startRule: "setPathname"})
      } catch (e) {
        this.exception = e.message
      }
    }
  },

  search: {
    enumerable: true,
    configurable: true,

    get: function() {
      if (this._query == null || this._query.length == 0) return "";
      return "?" + this._query
    },

    set: function(value) {
      try {
        UrlParser.parse(value.toString(), {url: this, startRule: "setSearch"})
      } catch (e) {
        this.exception = e.message
      }
    }
  },

  hash: {
    enumerable: true,
    configurable: true,

    get: function() {
      if (this._fragment == null || this._fragment.length == 0) return "";
      return "#" + this._fragment
    },

    set: function(value) {
      try {
        UrlParser.parse(value, {url: this, startRule: "setHash"})
      } catch (e) {
        this.exception = e.message
      }
    }
  }
})
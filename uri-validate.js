/*
Regex for URIs

These regex are directly derived from the collected ABNF in RFC3986
(except for DIGIT, ALPHA and HEXDIG, defined by RFC2234).

Additional regex are defined to validate the following schemes according to
their respective specifications:
  - http
  - https
  - file
  - data
  - gopher
  - ws
  - wss
  - mailto
  
See FIXME for areas that still need work.

JavaScript translation of https://gist.github.com/mnot/138549

Copyright (c) 2009-2015 Mark Nottingham (code portions)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

//// basics - 

var DIGIT = "[0-9]";
var ALPHA = "[A-Za-z]";
var HEXDIG = "[0-9A-Fa-f]";
var DQUOTE = "\"";

//   pct-encoded   = "%" HEXDIG HEXDIG
var pct_encoded = "%%" + HEXDIG + HEXDIG;

//   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
var unreserved = "(?:" + ALPHA + "|" + DIGIT + "|\\-|\\.|_|~)";

//   gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
var gen_delims = "(?::|/|\\?|#|\\[|\\]|@)";

//   sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
//                 / "*" / "+" / "," / ";" / "="
var sub_delims = "(?:!|\\$|&|'|\\(|\\)|\\*|\\+|,|;|=)";

//   pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
var pchar = "(?:" + unreserved + "|" + pct_encoded + "|" + sub_delims + "|:|@)";

//   reserved      = gen-delims / sub-delims
var reserved = "(?:" + gen_delims + "|" + sub_delims + ")";


//// scheme

//   scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
var scheme = ALPHA + "(?:" + ALPHA + "|" + DIGIT + "|\\+|\\-|\\.)*";


//// authority

//   dec-octet     = DIGIT                 ; 0-9
//                 / %x31-39 DIGIT         ; 10-99
//                 / "1" 2DIGIT            ; 100-199
//                 / "2" %x30-34 DIGIT     ; 200-249
//                 / "25" %x30-35          ; 250-255
var dec_octet = "(?:" + DIGIT + "|[1-9]" + DIGIT + "|1" + DIGIT + "{2}|2[0-4]" +
    DIGIT + "|25[0-5])";

//  IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
var IPv4address = dec_octet + "\\." + dec_octet + "\\." + dec_octet + "\\." +
    dec_octet;

//  h16           = 1*4HEXDIG
var h16 = "(?:" + HEXDIG + "){1,4}";

//  ls32          = ( h16 ":" h16 ) / IPv4address
var ls32 = "(?:(?:" + h16 + ":" + h16 + ")|" + IPv4address + ")";

//   IPv6address   =                            6( h16 ":" ) ls32
//                 /                       "::" 5( h16 ":" ) ls32
//                 / [               h16 ] "::" 4( h16 ":" ) ls32
//                 / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
//                 / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
//                 / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
//                 / [ *4( h16 ":" ) h16 ] "::"              ls32
//                 / [ *5( h16 ":" ) h16 ] "::"              h16
//                 / [ *6( h16 ":" ) h16 ] "::"
var IPv6address = "(?:(?:" + h16 + ":){6}" + ls32 + "|::(?:" + h16 + ":){5}" +
    ls32 + "|(?:" + h16 + ")?::(?:" + h16 + ":){4}" + ls32 + "|(?:(?:" + h16 +
    ":){0,1}" + h16 + ")?::(?:" + h16 + ":){3}" + ls32 + "|(?:(?:" + h16 +
    ":){0,2}" + h16 + ")?::(?:" + h16 + ":){2}" + ls32 + "|(?:(?:" + h16 +
    ":){0,3}" + h16 + ")?::" + h16 + ":" + ls32 + "|(?:(?:" + h16 + ":){0,4}" +
    h16 + ")?::" + ls32 + "|(?:(?:" + h16 + ":){0,5}" + h16 + ")?::" + h16 +
    "|(?:(?:" + h16 + ":){0,6}" + h16 + ")?::)";

//   IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
var IPvFuture = "v" + HEXDIG + "+\\.(?:" + unreserved + "|" + sub_delims +
    "|:)+";

//   IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
var IP_literal = "\\[(?:" + IPv6address + "|" + IPvFuture + ")\\]";

//   reg-name      = *( unreserved / pct-encoded / sub-delims )
var reg_name = "(?:" + unreserved + "|" + pct_encoded + "|" + sub_delims + ")*";

//   userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
var userinfo = "(?:" + unreserved + "|" + pct_encoded + "|" + sub_delims +
    "|:)*";

//   host          = IP-literal / IPv4address / reg-name
var host = "(?:" + IP_literal + "|" + IPv4address + "|" + reg_name + ")";

//   port          = *DIGIT
var port = "(?:" + DIGIT + ")*";

//   authority     = [ userinfo "@" ] host [ ":" port ]
var authority = "(?:" + userinfo + "@)?" + host + "(?::" + port + ")?";



//// Path

//   segment       = *pchar
var segment = pchar + "*";

//   segment-nz    = 1*pchar
var segment_nz = pchar + "+";

//   segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
//                 ; non-zero-length segment without any colon ":"
var segment_nz_nc = "(?:" + unreserved + "|" + pct_encoded + "|" + sub_delims +
    "|@)+";

//   path-abempty  = *( "/" segment )
var path_abempty = "(?:/" + segment + ")*";

//   path-absolute = "/" [ segment-nz *( "/" segment ) ]
var path_absolute = "/(?:" + segment_nz + "(?:/" + segment + ")*)?";

//   path-noscheme = segment-nz-nc *( "/" segment )
var path_noscheme = segment_nz_nc + "(?:/" + segment + ")*";

//   path-rootless = segment-nz *( "/" segment )
var path_rootless = segment_nz + "(?:/" + segment + ")*";

//   path-empty    = 0<pchar>
var path_empty = "";

//   path          = path-abempty    ; begins with "/" or is empty
//                 / path-absolute   ; begins with "/" but not "//"
//                 / path-noscheme   ; begins with a non-colon segment
//                 / path-rootless   ; begins with a segment
//                 / path-empty      ; zero characters
var path = "(?:" + path_abempty + "|" + path_absolute + "|" + path_noscheme +
    "|" + path_rootless + "|" + path_empty + ")";



//// Query and Fragment

//   query         = *( pchar / "/" / "?" )
var query = "(?:" + pchar + "|/|\\?)*";

//   fragment      = *( pchar / "/" / "?" )
var fragment = "(?:" + pchar + "|/|\\?)*";



//// URIs

//   hier-part     = "//" authority path-abempty
//                 / path-absolute
//                 / path-rootless
//                 / path-empty
var hier_part = "(?:(?://" + authority + path_abempty + ")|" + path_absolute +
    "|" + path_rootless + "|" + path_empty + ")";

//   relative-part = "//" authority path-abempty
//                 / path-absolute
//                 / path-noscheme
//                 / path-empty
var relative_part = "(?:(?://" + authority + path_abempty + ")|" +
    path_absolute + "|" + path_noscheme + "|" + path_empty + ")";

//   relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
var relative_ref = relative_part + "(?:\\?" + query + ")?(?:#" + fragment +
    ")?";

//   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
var URI = "(?:" + scheme + ":" + hier_part + "(?:\\?" + query + ")?(?:#" +
    fragment + ")?)";

//   URI-reference = URI / relative-ref
var URI_reference = "(?:" + URI + "|" + relative_ref + ")";

//   absolute-URI  = scheme ":" hier-part [ "?" query ]
var absolute_URI = "(?:" + scheme + ":" + hier_part + "(?:\\?" + query + ")?)";



//// HTTP[S] - RFC7230

// http-URI = "http:" "//" authority path-abempty [ "?" query ]
//             [ "#" fragment ]

var http_URI = "(?:http://" + authority + path_abempty + "(?:\\?" + query +
    ")?(?:#" + fragment + ")?)";

// https-URI = "https:" "//" authority path-abempty [ "?" query ]
//              [ "#" fragment ]

var https_URI = "(?:https://" + authority + path_abempty + "(?:\\?" + query +
    ")?(?:#" + fragment + ")?)";



//// WS[S] - RFC6455

// ws-URI = "ws:" "//" host [ ":" port ] path [ "?" query ]

var ws_URI = "(?:ws://" + host + "(?::" + port + ")?" + path + "(?:\\?" +
    query + ")?)";

// wss-URI = "wss:" "//" host [ ":" port ] path [ "?" query ]

var wss_URI = "(?:wss://" + host + "(?::" + port + ")?" + path + "(?:\\?" +
    query + ")?)";



//// mailto - RFC6068

// some-delims  = "!" / "$" / "'" / "(" / ")" / "*"
//            / "+" / "," / ";" / ":" / "@"

var some_delims = "(?:!|\\$|'|\\(|\\)|\\*\\+|,|;|:|@)";

// qchar        = unreserved / pct-encoded / some-delims

var qchar = "(?:" + unreserved + "|" + pct_encoded + "|" + some_delims + ")";

// dtext-no-obs = %d33-90 / ; Printable US-ASCII
//              %d94-126  ; characters not including
//                        ; "[", "]", or "\"

var dtext_no_obs = "(?:[!-[^-~])";

// atext           =   ALPHA / DIGIT /    ; Printable US-ASCII
//                     "!" / "#" /        ;  characters not including
//                     "$" / "%" /        ;  specials.  Used for atoms.
//                     "&" / "'" /
//                     "*" / "+" /
//                     "-" / "/" /
//                     "=" / "?" /
//                     "^" / "_" /
//                     "`" / "{" /
//                     "|" / "}" /
//                     "~"
// 
// dot-atom-text   =   1*atext *("." 1*atext)

var rfc5322_atext = "(?:" + ALPHA + "|" + DIGIT +
    "|!|#|\\$|%%|&|'|\\*|\\+|-|/|=|\\?|\\^|_|`|{|\\||}|~)";
var rfc5322_dot_atom_text = "(?:" + rfc5322_atext + "{1,}(?:." + rfc5322_atext +
    "{1,})*)";
var qcontent;
var rfc5322_FWS;
var rfc5322_CFWS;
qcontent = rfc5322_FWS = rfc5322_CFWS = "(?:)";

// quoted-string   =   [CFWS]
//                     DQUOTE *([FWS] qcontent) [FWS] DQUOTE
//                     [CFWS]

var rfc5322_quoted_string = "(?:(?:" + rfc5322_CFWS + ")?" + DQUOTE + "(?:(?:" +
    rfc5322_FWS + ")?" + qcontent + ")*(?:" + rfc5322_FWS + ")?" + DQUOTE +
    "(?:" + rfc5322_CFWS + ")?)";

// domain       = dot-atom-text / "[" *dtext-no-obs "]"

var domain = "(?:" + rfc5322_dot_atom_text + "|(?:\\[" + dtext_no_obs +
    "*\\]))";

// local-part   = dot-atom-text / quoted-string

var local_part = "(?:" + rfc5322_dot_atom_text + "|" + rfc5322_quoted_string +
    ")";

// addr-spec    = local-part "@" domain

var addr_spec = "(?:" + local_part + "@" + domain + ")";

// hfvalue      = *qchar

var hfvalue = "(?:" + qchar + "*)";

// hfname       = *qchar

var hfname = "(?:" + qchar + "*)";

// hfield       = hfname "=" hfvalue

var hfield = "(?:" + hfname + "=" + hfvalue + ")";

// to           = addr-spec *("," addr-spec )

var to = "(?:" + addr_spec + "(?:," + addr_spec + ")*)";

// hfields      = "?" hfield *( "&" hfield )

var hfields = "(?:\\?" + hfield + "(?:&" + hfield + ")*)";

// mailtoURI    = "mailto:" [ to ] [ hfields ]

var mailto_URI = "(?:mailto:(?:" + to + ")?(?:" + hfields + ")?)";


//// data - RFC2397 (+ RFC2045)

// ietf-token := <An extension token defined by a
//                standards-track RFC and registered
//                with IANA.>

var rfc2045_token = "(?:[0-z]+)";
var rfc2045_ietf_token = rfc2045_token;
var rfc2045_iana_tokens = rfc2045_token;
 
// x-token := <The two characters "X-" or "x-" followed, with
//             no intervening white space, by any token>

var rfc2045_x_token = "(?:[xX]-" + rfc2045_token + ")";

// extension-token := ietf-token / x-token

var rfc2045_extension_token = "(?:" + rfc2045_ietf_token + "|" +
    rfc2045_x_token + ")";

// discrete-type := "text" / "image" / "audio" / "video" /
//                  "application" / extension-token

var rfc2045_discrete_type = "(?:text|image|audio|video|application|" +
    rfc2045_extension_token + ")";

// composite-type := "message" / "multipart" / extension-token

var rfc2045_composite_type = "(?:message|multipart|" + rfc2045_extension_token +
    ")";

// type := discrete-type / composite-type

var rfc2045_type = "(?:" + rfc2045_discrete_type + "|" +
    rfc2045_composite_type + ")";

// subtype := extension-token / iana-token

var rfc2045_subtype = "(?:" + rfc2045_extension_token + "|" +
    rfc2045_iana_tokens + ")";

// parameter  := attribute "=" value
// attribute := token
//              ; Matching of attributes
//              ; is ALWAYS case-insensitive.
// 
// value := token / quoted-string

var rfc2045_quoted_string = "(?:)";
var rfc2045_attribute = "(?:" + rfc2045_token + ")";
var rfc2045_value = "(?:" + rfc2045_token + "|" + rfc2045_quoted_string + ")";
var rfc2045_parameter = "(?:" + rfc2045_attribute + "=" + rfc2045_value + ")";

// mediatype  := [ type "/" subtype ] *( ";" parameter )

var mediatype = "(?:(?:" + rfc2045_type + "/" + rfc2045_subtype + ")?(?:;" +
    rfc2045_parameter + ")*)";

// uric          = reserved | unreserved | escaped  // 2396
// data       := *urlchar

var rfc2396_uric = "(?:" + reserved + "|" + unreserved + "|" + pct_encoded +
    ")";
var data = "(?:" + rfc2396_uric + "*)";

// dataurl    := "data:" [ mediatype ] [ ";base64" ] "," data

var data_URI = "(?:data:(?:" + mediatype + ")?(?:;base64)?," + data + ")";

//// gopher - RFC4266

// gopher://<host>:<port>/<gopher-path>

var gopher_path = path;
var gopher_URI = "(?:gopher://" + host + ":" + port + "/" + gopher_path + ")";


//// file - draft-kerwin-file-scheme-13

// f-scheme       = "file"

var file_f_scheme = "(?:file)";
 
// f-auth         = [ userinfo "@" ] host

var file_f_auth = "(?:(?:" + userinfo + "@)?" + host + ")";
 
// unc-path       = 2*3"/" authority path-absolute

var file_unc_path = "(?:/{2,3}" + authority + path_absolute + ")";
 
// drive-marker   = ":" / "|"

var file_drive_marker = "(?::|\\|)";

// drive-letter   = ALPHA [ drive-marker ]

var file_drive_letter = "(?:" + ALPHA + "(?:" + file_drive_marker + ")?)";

// windows-path   = drive-letter path-absolute

var file_windows_path = "(?:" + file_drive_letter + path_absolute + ")";

// local-path     = path-absolute
//                / windows-path

var file_local_path = "(?:" + path_absolute + "|" + file_windows_path + ")";

// auth-path      = [ f-auth ] path-absolute
//                / unc-path
//                / windows-path

var file_auth_path = "(?:(?:" + file_f_auth + "?" + path_absolute + ")|" +
    file_unc_path + "|" + file_windows_path + ")";

// f-hier-part    = "//" auth-path
//                / local-path

var file_f_hier_part = "(?:(?://" + file_auth_path + ")|" + file_local_path +
    ")";

// file-URI       = f-scheme ":" f-hier-part [ "?" query ]

var file_URI = "(?:" + file_f_scheme + ":" + file_f_hier_part + "(?:\\?" +
    query + ")?)";

var known = {
  http: http_URI,
  https: https_URI,
  ws: ws_URI,
  wss: wss_URI,
  mailto: mailto_URI,
  data: data_URI,
  gopher: gopher_URI,
  file: file_URI
};

function uri_validate(string) {
  if (!new RegExp("^" + URI_reference + "$").test(string)) {
    return false
  } else if (string.indexOf(":") == -1) {
    return true
  } else {
    var scheme = string.split(":")[0].toLowerCase();
    if (!known[scheme]) return true;
    return new RegExp("^" + known[scheme] + "($|#" + fragment + ")").test(string)
  }
}

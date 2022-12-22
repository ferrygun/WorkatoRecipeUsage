import collections
import urequest1
import urequests
import netman
import time
import utime
import ujson
from machine import Pin
import gc

from umqttsimple import MQTTClient
from time import sleep


_hextobyte_cache = None

_ALWAYS_SAFE = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                         b'abcdefghijklmnopqrstuvwxyz'
                         b'0123456789'
                         b'_.-')
_ALWAYS_SAFE_BYTES = bytes(_ALWAYS_SAFE)
_safe_quoters = {}

def unquote(string):
    """unquote('abc%20def') -> b'abc def'."""
    global _hextobyte_cache

    # Note: strings are encoded as UTF-8. This is only an issue if it contains
    # unescaped non-ASCII characters, which URIs should not.
    if not string:
        return b''

    if isinstance(string, str):
        string = string.encode('utf-8')

    bits = string.split(b'%')
    if len(bits) == 1:
        return string

    res = [bits[0]]
    append = res.append

    # Build cache for hex to char mapping on-the-fly only for codes
    # that are actually used
    if _hextobyte_cache is None:
        _hextobyte_cache = {}

    for item in bits[1:]:
        try:
            code = item[:2]
            char = _hextobyte_cache.get(code)
            if char is None:
                char = _hextobyte_cache[code] = bytes([int(code, 16)])
            append(char)
            append(item[2:])
        except KeyError:
            append(b'%')
            append(item)

    return b''.join(res)

class Quoter(collections.defaultdict):
    """A mapping from bytes (in range(0,256)) to strings.

    String values are percent-encoded byte values, unless the key < 128, and
    in the "safe" set (either the specified safe set, or default set).
    """
    # Keeps a cache internally, using defaultdict, for efficiency (lookups
    # of cached keys don't call Python code at all).
    def __init__(self, safe):
        """safe: bytes object."""
        self.safe = _ALWAYS_SAFE.union(safe)

    def __repr__(self):
        # Without this, will just display as a defaultdict
        return "<Quoter %r>" % dict(self)

    def __missing__(self, b):
        # Handle a cache miss. Store quoted string in cache and return.
        res = chr(b) if b in self.safe else '%{:02X}'.format(b)
        self[b] = res
        return res
    
def quote(string, safe='/', encoding=None, errors=None):
    """quote('abc def') -> 'abc%20def'

    Each part of a URL, e.g. the path info, the query, etc., has a
    different set of reserved characters that must be quoted.

    RFC 2396 Uniform Resource Identifiers (URI): Generic Syntax lists
    the following reserved characters.

    reserved    = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" |
                  "$" | ","

    Each of these characters is reserved in some component of a URL,
    but not necessarily in all of them.

    By default, the quote function is intended for quoting the path
    section of a URL.  Thus, it will not encode '/'.  This character
    is reserved, but in typical usage the quote function is being
    called on a path where the existing slash characters are used as
    reserved characters.

    string and safe may be either str or bytes objects. encoding must
    not be specified if string is a str.

    The optional encoding and errors parameters specify how to deal with
    non-ASCII characters, as accepted by the str.encode method.
    By default, encoding='utf-8' (characters are encoded with UTF-8), and
    errors='strict' (unsupported characters raise a UnicodeEncodeError).
    """
    if isinstance(string, str):
        if not string:
            return string
        if encoding is None:
            encoding = 'utf-8'
        if errors is None:
            errors = 'strict'
        string = string.encode(encoding, errors)
    else:
        if encoding is not None:
            raise TypeError("quote() doesn't support 'encoding' for bytes")
        if errors is not None:
            raise TypeError("quote() doesn't support 'errors' for bytes")
    return quote_from_bytes(string, safe)

def quote_from_bytes(bs, safe='/'):
    """Like quote(), but accepts a bytes object rather than a str, and does
    not perform string-to-bytes encoding.  It always returns an ASCII string.
    quote_from_bytes(b'abc def\x3f') -> 'abc%20def%3f'
    """
    if not isinstance(bs, (bytes, bytearray)):
        raise TypeError("quote_from_bytes() expected bytes")
    if not bs:
        return ''
    if isinstance(safe, str):
        # Normalize 'safe' by converting to bytes and removing non-ASCII chars
        safe = safe.encode('ascii', 'ignore')
    else:
        safe = bytes([c for c in safe if c < 128])
    if not bs.rstrip(_ALWAYS_SAFE_BYTES + safe):
        return bs.decode()
    try:
        quoter = _safe_quoters[safe]
    except KeyError:
        _safe_quoters[safe] = quoter = Quoter(safe).__getitem__
    return ''.join([quoter(char) for char in bs])

def getSignSession():
    headers = {
            'Host': ' app.workato.com',
            'User-Agent': ' Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
            'Accept': ' application/json, text/plain, */*',
            'Accept-Language': ' en-US,en;q=0.5',
            'Referer': ' https://app.workato.com/users/sign_in',
            'Content-Type': ' application/json',
            'Connection': ' keep-alive',
            'Sec-Fetch-Dest': ' empty',
            'Sec-Fetch-Mode': ' cors',
            'Sec-Fetch-Site': ' same-origin'
        }
    response = urequest1.get('https://app.workato.com/web_api/auth_user.json', headers=headers)
    #print(response.text)
    x_csrf_token = response.cookies["XSRF-TOKEN"]
    _workato_app_session = response.cookies["_workato_app_session"]
    
    x_csrf_token = unquote(x_csrf_token).decode('utf-8').split(';')[0]
    _workato_app_session = unquote(_workato_app_session).decode('utf-8').split(';')[0]
    response.close()
    return x_csrf_token, _workato_app_session

def getSession(x_csrf_token, _workato_app_session):
    headers = {
            'Host': ' app.workato.com',
            'User-Agent': ' Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
            'Accept': ' application/json, text/plain, */*',
            'Accept-Language': ' en-US,en;q=0.5',
            'Referer': ' https://app.workato.com/users/sign_in',
            'X-CSRF-TOKEN': x_csrf_token,
            'X-Requested-With': ' XMLHttpRequest',
            'Content-Type': ' application/json',
            'Origin': ' https://app.workato.com',
            'Connection': ' keep-alive',
            'Cookie': '; _workato_app_session=' + _workato_app_session,
            'Sec-Fetch-Dest': ' empty',
            'Sec-Fetch-Mode': ' cors',
            'Sec-Fetch-Site': ' same-origin'
        }
    
    body = '{"user":{"email":"WORKATO_USERID","password":"WORKATO_PWD"}}'
    response = urequest1.post('https://app.workato.com/users/sign_in.json', data=body, headers=headers)
    #print(response.text)
    
    x_csrf_token = response.cookies["XSRF-TOKEN"]
    _workato_app_session = response.cookies["_workato_app_session"]
    
    x_csrf_token = unquote(x_csrf_token).decode('utf-8').split(';')[0]
    _workato_app_session = unquote(_workato_app_session).decode('utf-8').split(';')[0]
    response.close()
    return x_csrf_token, _workato_app_session


def getSubscription(xsrf_token, workato_app_session):
    headers = {
            'Host': ' app.workato.com',
            'User-Agent': ' Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
            'Accept': ' text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': ' en-US,en;q=0.5',
            'Connection': ' keep-alive',
            'Cookie': ' XSRF-TOKEN=' + xsrf_token + '; _workato_app_session=' + workato_app_session + '; ',
            'Upgrade-Insecure-Requests': ' 1',
            'Sec-Fetch-Dest': ' document',
            'Sec-Fetch-Mode': ' navigate',
            'Sec-Fetch-Site': ' none',
            'Sec-Fetch-User': ' ?1'
        }
    
    response = urequests.get('https://app.workato.com/users/current/edit.json', headers=headers)
    res = response.json()["result"]
    res = res["billable_flow_count"]
    response.close()                   
    return res

#MQTT connect
def mqtt_connect():
    client = MQTTClient(client_id, mqtt_server, user=user_t, password=password_t, keepalive=60)
    client.connect()
    print('Connected to %s MQTT Broker'%(mqtt_server))
    return client

#reconnect & reset
def reconnect():
    print('Failed to connected to MQTT Broker. Reconnecting...')
    time.sleep(5)
    machine.reset()

def callback(topic, msg): 
    print((topic, msg))
    msg = msg.decode('UTF-8')

        
country = 'SG'
ssid = 'SSID'
password = 'PWD'
wifi_connection = netman.connectWiFi(ssid,password,country)

#mqtt config
mqtt_server = 'HOME_ASSISTANT_MQTT_SERVER'
client_id = 'PicoW'
user_t = 'MQTT_USERID'
password_t = 'MQTT_PWD'
topic_pub = 'hello'

while True:   
    try:
        client = mqtt_connect()
    except OSError as e:
        reconnect()
        
    while True:
        try:
            gc.collect()
            x_csrf_token, _workato_app_session = getSignSession()
            gc.collect()
            x_csrf_token, _workato_app_session = getSession(x_csrf_token, _workato_app_session)
            gc.collect()
            reading = getSubscription(x_csrf_token, _workato_app_session)
            
            client.publish(topic_pub, msg=str(round(reading)))
            print('published')
            time.sleep(1)
        except:
            reconnect()
            pass
    client.disconnect()
    

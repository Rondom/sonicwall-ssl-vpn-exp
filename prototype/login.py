#!/bin/env python3
import argparse
import json
import logging
import re
import requests

logger = logging.getLogger(__name__)
# needs to contain NetExtender string, otherwise we get asked to upgrade
USER_AGENT = f'SonicWALL NetExtender for Linux 9.0.803 (compatible; {__name__})'
COOKIE_NAME = 'swap'


def parse_cli_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', metavar='HOST[:PORT]', help='host:port, port is 443 by default')
    parser.add_argument('--domain', metavar="DOMAIN", help='domain')
    parser.add_argument('--user', metavar="USER", help='user')
    parser.add_argument('--password', metavar="PASSWORD", help='password')
    args = parser.parse_args()
    return args


def main():
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())

    args = parse_cli_args()

    server = args.server
    if not server.startswith('https://'):
        server = 'https://' + server

    cookie_jar = login(server, args.domain, args.user, args.password)
    logger.info("Got cookie: (hidden)")
    logger.debug("Got cookie: %s", cookie_jar)

    epc_version = get_epc_information(server, cookie_jar)
    logger.info("Got EPC info (currently unsupported): %s", epc_version)

    params = get_connection_parameters(server, cookie_jar)
    logger.debug(params)

    output = {
        'cookie': cookie_jar[COOKIE_NAME],
        'params': params,
    }
    print(json.dumps(output, sort_keys=True, indent=4))


def login(server, domain, user, password):
    """
    Does login, return cookie jar with cookies on success
    """
    """
    POST /cgi-bin/userLogin HTTP/1.0
    Content-Type: application/x-www-form-urlencoded
    User-Agent: SonicWALL NetExtender for Linux 9.0.803
    Host: 127.0.0.1:8443
    Content-Length: 60
    Cache-Control: no-cache
    X-NE-pda: true
    
    username=demo&password=password&domain=SMA%2DDemo&login=true
    """
    """
    HTTP/1.1 200 OK
    Date: Sun, 19 Apr 2020 00:01:18 GMT
    Server: SonicWALL SSL-VPN Web Server
    X-NE-tf: 0
    MC-bookmarks: 3
    Set-Cookie: swap=dURBeDZPWXNycUI1TTMyakk2RzhqZXJGTEsycEpnWGowcHBEY3pPek1KVT0=; path=/; secure; HttpOnly
    X-FRAME-OPTIONS: SAMEORIGIN
    X-XSS-Protection: 1; mode=block
    Content-Security-Policy: script-src https://*.duosecurity.com 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'self'; style-src 'self' 'unsafe-inline'
    Referrer-Policy: strict-origin
    X-Content-Type-Options: nosniff
    Content-Length: 144
    Connection: close
    Content-Type: text/html; charset=UTF-8
    
    <HTML><HEAD><META HTTP-EQUIV="Pragma" CONTENT="no-cache"><meta http-equiv="refresh" content="0; URL=/cgi-bin/portal"></HEAD><BODY></BODY></HTML>
    """

    url = f'{server}/cgi-bin/userLogin'
    response = requests.post(url,
                             headers={
                                 'User-Agent': USER_AGENT,
                                 'X-NE-pda': 'true',
                             },
                             data={
                                 'username': user,
                                 'password': password,
                                 'domain': domain,
                                 'login': 'true'
                             })
    logger.debug("Login response headers: %s", response.headers)
    logger.debug("Login response text: %s", response.text)
    if response.status_code != 200:
        raise Exception(f"Did not get 200 on login: {response}")
    if COOKIE_NAME not in response.cookies:
        raise Exception(f"Could not login: {response.headers.get('X-NE-message')}, {response.text}")
    return response.cookies


def get_epc_information(server, cookie_jar):
    """
    Get EPC information (that's some mechanism like HostChecker)
    """
    """
    GET /cgi-bin/sslvpnclient?epcversionquery=nxx HTTP/1.0
    Accept: */*
    Accept-Language: en-us
    User-Agent: SonicWALL NetExtender for Linux 9.0.803
    Host: 127.0.0.1:8443
    Cookie: swap=dURBeDZPWXNycUI1TTMyakk2RzhqZXJGTEsycEpnWGowcHBEY3pPek1KVT0=;
    
    HTTP/1.1 200 OK
    Date: Sun, 19 Apr 2020 00:01:20 GMT
    Server: SonicWALL SSL-VPN Web Server
    X-FRAME-OPTIONS: SAMEORIGIN
    X-XSS-Protection: 1; mode=block
    Content-Security-Policy: script-src https://*.duosecurity.com 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'self'; style-src 'self' 'unsafe-inline'
    Referrer-Policy: strict-origin
    X-Content-Type-Options: nosniff
    Content-Length: 22
    Connection: close
    Content-Type: text/html; charset=UTF-8
    """
    """
    NX_LINUX_EPC_VER: 0;
    """
    response = requests.get(server + '/cgi-bin/sslvpnclient?epcversionquery=nxx',
                            headers={
                                'User-Agent': USER_AGENT,
                            },
                            cookies=cookie_jar
                            )
    logger.debug("EPC response: %s", repr(response.text))
    return response.text


IGNORE_LINE_RE = re.compile(r'^(.*</html>|<html>.*)$')
KV_LINE_RE = re.compile(r'^\s*(?P<key>\S+)\s*=\s*(?P<value>.+?);?\s*$')


def get_connection_parameters(server, cookie_jar):
    """
    Gets connection parameters such as routes, DNS servers etc.
    """
    """
    GET /cgi-bin/sslvpnclient?launchplatform=mac&neProto=3&supportipv6=yes HTTP/1.0
    Content-Type: application/x-www-form-urlencoded
    User-Agent: SonicWALL NetExtender for Linux 9.0.803
    Host: 127.0.0.1:8443
    Content-Length: 0
    Cache-Control: no-cache
    X-NE-pda: true
    Cookie: swap=dURBeDZPWXNycUI1TTMyakk2RzhqZXJGTEsycEpnWGowcHBEY3pPek1KVT0=
    """
    """
    <html><head><meta http-equiv='Content-Type' content='text/html;charset=UTF-8'><title>SonicWall SMA 10.0 Demonstration Site</title><meta http-equiv='pragma' content='no-cache'><meta http-equiv='cache-control' content='no-cache'><meta http-equiv='cache-control' content='must-revalidate'><META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW"><link href='/themes/styleblueblackgrey.10.0.0.1-19sv.css' rel=stylesheet type='text/css'>
    SessionId = uDAx6OYsrqB5M32jI6G8jerFLK2pJgXj0ppDczOzMJU=
    Route = 192.168.150.0/255.255.255.0
    Route = 192.168.150.0/255.255.255.0
    ipv6Support = no
    Compression = yes
    dns1 = 192.168.150.111
    dns2 = 192.168.150.112
    pppFrameEncoded = 0
    PppPref = async
    displayName = Demo User
    NX_TUNNEL_PROTO_VER = 2.0
    dnsSuffix = sma-demo.com
    dnsSuffixes = sma-demo.com
    TunnelAllMode = 0
    UninstallAfterExit = 0;
    ExitAfterDisconnect = 1;
    NoProfileCreate = 0;
    AllowSavePassword = 0;
    AllowSaveUser = 1;
    AllowSavePasswordInKeychain = 1;
    AllowSavePasswordInKeystore = 1;
    AllowSavePasswordInKeychainMac = 0;
    AllowSavePasswordInKeychainFaceIDiOS = 0;
    AllowDisableUpdate = 0;
    </html>
    """
    response = requests.get(server + '/cgi-bin/sslvpnclient?launchplatform=mac&neProto=3&supportipv6=yes',
                            # '/cgi-bin/sslvpnclient',
                            headers={
                                'User-Agent': USER_AGENT,
                                'X-NE-pda': 'true',
                            },
                            # data={
                            #    'launchplatform': 'mac',
                            #    'neProto': '3',
                            #    'supportipv6': 'yes',
                            # },
                            cookies=cookie_jar,
                            )
    lines = response.text.splitlines()
    params = {}
    # One some servers it is wrapped in script tags
    # still you have variable names appearing multiple times, so it is not JS
    # some values are quoted some not
    for line in lines:
        if IGNORE_LINE_RE.match(line):
            logger.debug("Skipping: %s", line)
            continue
        match = KV_LINE_RE.match(line)
        if not match:
            logger.warning("No match for line: %s", line)
            continue
        (key, value) = match.groups()
        # some values are quoted (known so far: ClientIPHigh, ClientIPLow)
        value = value.strip('"')
        if key not in params:
            params[key] = value
        else:
            # some variables can appear multiple times, until we know which ones,
            # store them as list (as of now, it is "Ipv6Route" and "Route")
            if isinstance(params[key], list):
                params[key].append(value)
            else:
                params[key] = [params[key], value]
    return params


if __name__ == "__main__":
    main()

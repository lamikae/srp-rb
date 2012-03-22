#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Example of SRP client authentication.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the Python Software Foundation nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL TOM COCAGNE BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
import sys, json, urllib, urllib2
import pysrp as srp

def authenticate_over_http(host, username, password, ng_type=0):
    usr      = srp.User( username, password, ng_type=ng_type )
    uname, A = usr.start_authentication()

    # The authentication process can fail at each step from this
    # point on. To comply with the SRP protocol, the authentication
    # process should be aborted on the first failure.

    url = "http://%s/authenticate" % (host)

    # Client => Server: username, A
    print "start authentication"
    print "A:", A
    payload = {"username": uname, "A": A}
    data = urllib.urlencode(payload)    # Use urllib to encode the parameters
    try:
        request = urllib2.Request(url, data)
        response = urllib2.urlopen(request)    # This request is sent in HTTP POST
    except Exception, e:
        print e
        return False

    # Server => Client: s, B
    challenge = json.loads(response.read())
    B = challenge["B"]
    s = challenge["salt"]
    print "B:", B
    print "salt:", s

    M = usr.process_challenge( s, B )
    H_AMK = usr.H_AMK

    print "client M:", M
    print "client H(AMK):", H_AMK

    # Client => Server: M
    payload = {"username": uname, "M": M}
    data = urllib.urlencode(payload)    # Use urllib to encode the parameters
    try:
        request = urllib2.Request(url, data)
        response = urllib2.urlopen(request)    # This request is sent in HTTP POST
    except Exception, e:
        print e
        return False

    verification = json.loads(response.read())

    if "H_AMK" in verification:
        server_H_AMK = verification["H_AMK"]
        print "server H(AMK):", server_H_AMK
        if server_H_AMK == H_AMK:
            return True
        else:
            print "server H(AMK) does not match"

    return False

if __name__ == '__main__':
    host = "localhost:4567"
    try:
        username = sys.argv[1]
        password = sys.argv[2]
    except:
        print "give username and password in parameters"
        sys.exit(1)
    # ng_type is a constant for choosing prime length N and g.
    # server has to use the same value!
    NG_1024   = 0
    NG_2048   = 1
    NG_4096   = 2
    NG_8192   = 3
    if authenticate_over_http(host, username, password, ng_type=0):
        print "authentication successful"
    else:
        print "authentication failed"


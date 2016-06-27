#Copyright 2016 Graeme James McGibbney
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
'''
Input commentary over what the code is intended to do.
'''
import sqlite3

dnsResponseCodes = ['NOERROR','FORMERR','SERVFAIL','NXDOMAIN','NOTIMP','REFUSED','YXDOMAIN','XRRSET','NOTAUTH','NOTZONE']

fhand = open('test.txt')
dnsDict = {}
dnsList = ()
iD = 0

for line in fhand:
    if dnsResponseCodes[0] in line:
        date = line[0:6]
        print date
        time = line[7:15]
        print time
        line = line.rstrip()
        data = line[181:]
        data = data.strip(')(1234567890')
        newData = data.replace('(', '.')
        dns = newData.translate(None, "()123456789")
        dnsList = (date, time, dns)
        print dnsList
        dnsDict[iD] = dnsList
        print dnsDict
        iD += 1

print dnsDict

try:
    conn = sqlite3.connect('dnscoll.sqlite')
    cur = conn.cursor()
except:
    print "error"

for dnsmatch in dnsDict:
    result = cur.execute("SELECT * FROM Collect WHERE domain='%s'" % dnsmatch)
print result.fetchall()
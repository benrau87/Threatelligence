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

'''
import sqlite3

#Prepare database
conn = sqlite3.connect('dnscorr.sqlite')
cur = conn.cursor()

cur.execute('''
DROP TABLE IF EXISTS dns''')

cur.execute('''
CREATE TABLE dns (Date TEXT, Time TEXT, dns_request TEXT)''')


fhand = open('test.txt')
dnsDict = {}
dnsList = ()
iD = 0
# data = fhand.find("]")
# print data

for line in fhand:
    if 'NOERROR]' in line:
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
        dnsDict[iD] = {dnsList}
        print dnsDict
        iD += 1

        #cur.execute('''INSERT INTO dns (Date,Time,dns_request)
        #   VALUES (?, ?, ?)''', (date, time, dns))
#conn.commit()
print dnsDict

try:
    conn = sqlite3.connect('dnscoll.sqlite')
    cur = conn.cursor()
except:
    print "error"

for dnsmatch in dnsDict:
    result = cur.execute("SELECT * FROM database_servers WHERE InstalledApplications='%s' UNION ALL "
                     "SELECT * FROM email_servers WHERE InstalledApplications='%s' UNION ALL "
                     "SELECT * FROM dev_servers WHERE InstalledApplications='%s' UNION ALL "
                     "SELECT * FROM domain_controllers WHERE InstalledApplications='%s' UNION ALL "
                     "SELECT * FROM exchange WHERE InstalledApplications='%s' UNION ALL "
                     "SELECT * FROM file_transfer WHERE InstalledApplications='%s' UNION ALL "
                     "SELECT * FROM huxley WHERE InstalledApplications='%s' UNION ALL "
                     "SELECT * FROM pas WHERE InstalledApplications = '%s'"
                     % (dnsmatch, dnsmatch, dnsmatch, dnsmatch, dnsmatch, dnsmatch, dnsmatch, dnsmatch))
print result.fetchall()
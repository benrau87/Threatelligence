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
dnscorr.py is a script designed to take a dns log file, parse for the date,
time and request of the call and then store these values inside list dnsList
These listed items are then stored inside dnsDict dictionary with a count
variable used as the incremental key value. The script then connects to the
dnscoll.sqlite database which holds data on domains that are known to be used to propogate malware and spyware.
Using the parsed dns query from the dns log the script looks for
a correlation between the dns element and the database.
For a positive correlation the script then retrieves the
date and time of the event values held within the dnsList stored within dnsDict.
After all values within dnsList are retrieved the entire list
value is placed within ElasticSearch.
In order for this script to run, a local sqlite3 DB named
'dnscoll.sqlite' must be within the same directory as this
script.
Finally, it is assumed that Elasticsearch is available at
http://127.0.0.1:9200 such that affected systems and the
severity of the threat can be written into records for display
in Kibana.
'''
import sqlite3
from elasticsearch import Elasticsearch,helpers

#Create an array of possible DNS return codes to indicate whtether the DNS query has been successful or resulte in an error
#https://support.opendns.com/entries/60827730-FAQ-What-are-common-DNS-return-or-response-codes-

dnsResponseCodes = ['NOERROR','FORMERR','SERVFAIL','NXDOMAIN','NOTIMP','REFUSED','YXDOMAIN','XRRSET','NOTAUTH','NOTZONE']

fhand = open('test.txt')

#The dnsList will capture all parese vlaues from the txt file, these list valeus will then be stored in dnsDict

dnsList = []
dnsDict = {}

iD = 0

# for loop interates through the dns txt file selecting lines containing the dns response code 'NO ERROR'
# Each data element will go through a normalisation process to ensure that the format is consistent with
# the data stored in the dnscoll.sqlite.

for line in fhand:
    if dnsResponseCodes[0] in line:
        date = line[0:6]
        time = line[7:15]
        line = line.rstrip()
        data = line[181:]
        data = data.strip(')(1234567890')
        newData = data.replace('(', '.')
        dns = newData.translate(None, "()123456789")
        #dnsList = [unicode(date),unicode(time),unicode(dns)]
        dnsList = [date, time, dns]
        dnsDict[iD] = dnsList
        iD += 1

print dnsDict

# Connect to dnscoll.sqlite this database contains a list of domiains known to propogate malware or spyware

conn = sqlite3.connect('dnscoll.sqlite')
cur = conn.cursor()

for dnsListKey,dnsListValue in dnsDict.iteritems():
    try:
        result = cur.execute("SELECT * FROM Collect WHERE domain = '%s'" % unicode(dnsListValue[2]))
        print result.fetchall()
    except sqlite3.Error as e:
        print "An error occurred whilst querying the DNS collection database:", e.args[0]

listOfThreats = []

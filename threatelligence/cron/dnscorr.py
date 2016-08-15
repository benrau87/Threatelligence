# Copyright 2016 Graeme James McGibbney
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# dnscorr.py is a script designed to take a dns log file, parse for the date,
# time and request of the call and then store these values inside list dnsList
# These listed items are then stored inside dnsDict dictionary with a count
# variable used as the incremental key value. The script then connects to the
# dnscoll.sqlite database which holds data on domains that are known to be used to propogate malware and spyware.
# Using the parsed dns query from the dns log the script looks for
# a correlation between the dns element and the database.
# For a positive correlation the script then retrieves the
# date and time of the event values held within the dnsList stored within dnsDict.
# After all values within dnsList are retrieved the entire list
# value is placed within ElasticSearch.
# In order for this script to run, a local sqlite3 DB named
# 'dnscoll.sqlite' must be within the same directory as this
# script.
# Finally, it is assumed that Elasticsearch is available at
# http://127.0.0.1:9200 such that affected systems and the
# severity of the threat can be written into records for display
# in Kibana.
import sqlite3
import time
from datetime import timedelta
import os
import string
from intelnotification import IntelNotify
from elasticsearch import Elasticsearch
from urllib.parse import urlparse

def chunk2ip(chunk):
    ret=''
    bracketmode = False
    for c in chunk:
        if bracketmode:
            if c != ')':
                pass #dispose char
            else:
                if len(ret)>0:
                    ret += '.'
                bracketmode = False
        else:
            if c != '(':
                ret += c
            else:
                bracketmode = True
    return ret[:len(ret)-1]

startTime = time.time()
#Create an array of possible DNS return codes to indicate whtether the DNS query has been successful or resulte in an error
#https://support.opendns.com/entries/60827730-FAQ-What-are-common-DNS-return-or-response-codes-
dnsResponseCodes = ['NOERROR','FORMERR','SERVFAIL','NXDOMAIN','NOTIMP','REFUSED','YXDOMAIN','XRRSET','NOTAUTH','NOTZONE']

fhand = open('dns10000.txt')

# The dnsList will capture all parsed values from the txt file, these list values will then be stored in dnsDict

dnsList = []
dnsDict = {}

iD = 0

# for loop iterates through the dns txt file selecting lines containing the dns response code 'NO ERROR'
# Each data element will go through a normalisation process to ensure that the format is consistent with
# the data stored in the dnscoll.sqlite.

for line in fhand:
    if dnsResponseCodes[0] in line:
        date = line[0:6]
        timeStr = line[7:15]
        line = line.rstrip()
        data = line[178:]
        dns = (chunk2ip(data))
        dnsList = [date, timeStr, str(dns)]
        dnsDict[str(dns)] = dnsList
        iD += 1

# Connect to dnscoll.sqlite this database contains a list of domiains known to propogate malware or spyware
conn = sqlite3.connect('dnscoll.sqlite')
cur = conn.cursor()
dnsCorrellations = []
count = 0
for dnsListKey,dnsListValue in dnsDict.items():
    try:
        domain = urlparse(str('http://') + dnsListValue[2])
        result = cur.execute("SELECT * FROM collect WHERE malware_domain LIKE '%s'" % domain.netloc)
        for match in result.fetchall():
            m = match[0]
            if m in dnsDict.keys():
                tTuple = (m, dnsDict[match[0]],)
                dnsCorrellations.append(tTuple)

    except sqlite3.Error as e:
        print("An error occurred whilst querying the DNS collection database:", e.args[0])
conn.close()

# We'll now build up a Python dictionary of our data set in a format that the
# Python ES client can use. We are going to load the data by means of bulk
# indexing. According to the Elasticsearch Bulk API docs, the body of the bulk
# index request must consist of two lines for each operation: one specifying the
# meta-data for the operation; and one specifying the actual data that it will
# index. The code below will build a dictionary that meets these requirements
# for our data:

bulk_data = []
systemList = ['Date','Time','DNS']
for dns in dnsCorrellations:
    data_dict = {}
    count = 0
    for item in dns[1]:
        data_dict[systemList[count]] = dns[1][count]
        count += 1
    op_dict = {
        "index": {
            "_index": 'threatelligence',
            "_type": 'MalwareDNS',
        }
    }
    bulk_data.append(op_dict)
    bulk_data.append(data_dict)

endTime = time.time()

# Let's create our index using the Python ES client.
# By default we assume the aserver is running on http://localhost:9200
es = Elasticsearch(hosts=['localhost:9200'])
# bulk index the data
res = es.bulk(index = 'threatelligence', body=bulk_data, refresh = True)

# sends email notification
email = IntelNotify()
email.send_mail(len(dnsCorrellations),(endTime - startTime), os.path.basename(__file__))
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
Script which acquires Microsoft security vulnerability patches
and determines whether internal systems are affected and 
potentially vulnerable. Affected systems are written into
Elasticsearch.
Microsoft publishes security patches on the second Tuesday 
of each month therefore this script should be run as a cron
job to suite the patch publication pattern.
In order for this script to run, a local sqlite3 DB named
'asset_base2.sqlite' must be within the same directory as this
script.
Finally, it is assumed that Elasticsearch is available at
http://127.0.0.1:9200 such that affected systems and the 
severity of the threat can be written into records for display
in Kibana.

The crontab below defines this script to run at 1am on the 2nd tuesday of every month.
10 18 8-14 * 2 /usr/bin/python /path/to/vulncorr.py
For other examples of how to reference a cron job use this link:
https://github.com/gfunkoriginal/Threatelligence/blob/master/Install.md#cron
'''
import sqlite3
import urllib.request
import json
import datetime
from elasticsearch import Elasticsearch
import time
from intelnotification import IntelNotify
import os
import sys
from datetime import timedelta
import string

# Obtaining the date enables dynamic date variable 
# substitution whenever the script is run.
# TODO this could potentially be improved by checking
# for the second Tuesday of every month, however seeing
# as the script is being run as a cron job, we can simply
# invoke it only on the second Tuesday of each month hence
# guaranteeing the dates match perfectly.
indexName = 'threatelligence'
startTime = time.time()

# i = datetime.datetime.now()
# fHand = urllib.urlopen("http://isc.sans.edu/api/getmspatchday/%s-%s-%s?json" % (i.year, i.month, i.day))
fHand = urllib.request.urlopen('http://isc.sans.edu/api/getmspatchday/2016-01-12?json')
#fHand = open("vulnTest.txt")

#data = fHand.read()
data = fHand.read().decode('utf-8')
js = json.loads(data)

# The patchDict below will enable us to capture both 
# affected system(s) as well as the severity of each threat
patchDict = {}
vulnDict = {}

# Populate the patchDict variable with Key Value pairs 
# representing the affected application and severity of 
# patch respectively.
for record in js["getmspatchday"]:
    patchID = record["id"]
    affected = record["affected"]
    severity = record["severity"]
#    patchDict[str(affected)] = str(patchID), str(severity)
    patchDict[str(affected)] = str(severity)
    vulnDict [str(patchID)]= affected, severity

# Make connection to internal asset database
conn = sqlite3.connect('asset_base2.sqlite')
cur = conn.cursor()

listOfThreats = []

# Need to create another data structure which results can be appended to.
# This will enable us to index the results in a batch oriented fashion.
# Currently task of searching through dictionary looks only for exact matches against a
# given asset within the database. No fuzzy searches are carried out. This is a possible
# future improvement to the application.
for patch in vulnDict:
    lookup = vulnDict[patch][0]
    try:

        result = cur.execute("SELECT * FROM database_servers WHERE InstalledApplications LIKE '%s' OR InstalledApplications LIKE 'Windows ' || '%s' UNION ALL "
                         "SELECT * FROM email_servers WHERE InstalledApplications LIKE '%s' OR InstalledApplications LIKE 'Windows ' || '%s' UNION ALL "
                         "SELECT * FROM dev_servers WHERE InstalledApplications LIKE '%s' OR InstalledApplications LIKE 'Windows ' || '%s' UNION ALL "
                         "SELECT * FROM domain_controllers WHERE InstalledApplications LIKE '%s' OR InstalledApplications LIKE 'Windows ' || '%s' UNION ALL "
                         "SELECT * FROM exchange WHERE InstalledApplications LIKE '%s' OR InstalledApplications LIKE 'Windows ' || '%s' UNION ALL "
                         "SELECT * FROM file_transfer WHERE InstalledApplications LIKE '%s' OR InstalledApplications LIKE 'Windows ' || '%s' UNION ALL "
                         "SELECT * FROM huxley WHERE InstalledApplications LIKE '%s' OR InstalledApplications LIKE 'Windows ' || '%s' UNION ALL "
                         "SELECT * FROM pas WHERE InstalledApplications LIKE '%s' OR InstalledApplications LIKE 'Windows ' || '%s' "
                         % (lookup, lookup, lookup, lookup, lookup, lookup, lookup, lookup, lookup, lookup, lookup, lookup, lookup, lookup, lookup, lookup))
        affectedSystem = []
        for system in result.fetchall():
            affectedSystem = (patchID, vulnDict[patchID],) + system
            listOfThreats.append(affectedSystem)
    except sqlite3.Error as e:
        print("An error occurred whilst querying the asset database:", e.args[0])

# Close connection to asset database
conn.close()
if not listOfThreats:
    sys.exit

# We'll now build up a Python dictionary of our data set in a format that the 
# Python ES client can use. We are going to load the data by means of bulk 
# indexing. According to the Elasticsearch Bulk API docs, the body of the bulk 
# index request must consist of two lines for each operation: one specifying the 
# meta-data for the operation; and one specifying the actual data that it will 
# index. The code below will build a dictionary that meets these requirements 
# for our data:

bulk_data = [] 
systemList = ['PatchID','Severity','Name','DeviceType','InstalledApplictions','ApplicationVersion',
              'Description','OperatingSystem','OperatingSystemVersion','Groups']
for threat in listOfThreats:
    data_dict = {}
    count = 0
    for item in threat:
        data_dict[systemList[count]] = item
        count += 1
    op_dict = {
        "index": {
            "_index": indexName,
            "_type": 'VulnerableSystem',
        }
    }
    bulk_data.append(op_dict)
    bulk_data.append(data_dict)

# Let's create our index using the Python ES client.
# By default we assume the aserver is running on http://localhost:9200
es = Elasticsearch(hosts=['localhost:9200'])
# bulk index the data
res = es.bulk(index = indexName, body = bulk_data, refresh = True)

endTime = time.time()
# sends email notification
email = IntelNotify()
email.send_mail(len(listOfThreats), (endTime - startTime), os.path.basename(__file__))
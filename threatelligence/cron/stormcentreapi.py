import sqlite3
import urllib
import json
import datetime

# Obtaining the date enables dynamic date variable 
# substitution whenever the script is run.
# TODO this could potentially be improved by checking
# for the second Tuesday of every month, however seeing
# as the script is being run as a cron job, we can simply
# invoke it only on the second Tuesday of each month hence
# guaranteeing the dates match perfectly.

#i = datetime.datetime.now()
#fHand = urllib.urlopen("http://isc.sans.edu/api/getmspatchday/%s-%s-%s?json" % (i.year, i.month, i.day))
fHand = urllib.urlopen('http://isc.sans.edu/api/getmspatchday/2016-01-12?json')

print fHand.getcode()

data = fHand.read()

js = json.loads(data)

print json.dumps(js, indent=4)

#threatList = []
# The threatDict below which will enable us to capture
# both affected as well as threat criticality.
threatDict = {}
count = 0

#The code below populates the threatDict variable with
# Key Value pairs representing the affected application and
# severity of patch respectively.
for record in js["getmspatchday"]:
    affected = record["affected"]
    severity = record["severity"]
    threatDict[str(affected)] = str(severity)
    ++count

print threatDict
try:
    conn = sqlite3.connect('asset_base2.sqlite')
    cur = conn.cursor()
except:
    print "error"

# Need to create another data structure which results can be appended to.
# This will enable us to index the results in a batch oriented fashion.
for threat in threatDict:

# Consider the following code, this will pull out the 
# affected application as one element of the list of
# dictionary keys, this basically does the same as we
# did previously with the threatList however it now also
# enables us to retain and utilize the criticality of each
# application vulnerability.
    result = cur.execute("SELECT * FROM database_servers WHERE InstalledApplications='%s' UNION ALL "
                         "SELECT * FROM email_servers WHERE InstalledApplications='%s' UNION ALL "
                         "SELECT * FROM dev_servers WHERE InstalledApplications='%s' UNION ALL "
                         "SELECT * FROM domain_controllers WHERE InstalledApplications='%s' UNION ALL "
                         "SELECT * FROM exchange WHERE InstalledApplications='%s' UNION ALL "
                         "SELECT * FROM file_transfer WHERE InstalledApplications='%s' UNION ALL "
                         "SELECT * FROM huxley WHERE InstalledApplications='%s' UNION ALL "
                         "SELECT * FROM pas WHERE InstalledApplications = '%s'"
                         % (threat, threat, threat, threat, threat, threat, threat, threat))
    print result.fetchall()


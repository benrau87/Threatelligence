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
i = datetime.datetime.now()
fHand = urllib.urlopen("http://isc.sans.edu/api/getmspatchday/%s-%s-%s?json" 
    % (i.year, i.month, i.day))

print fHand.getcode()

data = fHand.read()

js = json.loads(data)

print json.dumps(js, indent=4)

threatList = []
count = 0

#To do, we wish to pull out the criticality of the patch as well as the system affected
for record in js["getmspatchday"]:
    threat = record["affected"]
    threatList.insert(count, threat)
    ++count

#print threatList
try:
    conn = sqlite3.connect('asset_base2.sqlite')
    cur = conn.cursor()
except:
    print "error"
# Need to create another data structure which results can be appended to.
# This will enable us to index the results in a batch oriented fashion.
for threat in threatList:
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


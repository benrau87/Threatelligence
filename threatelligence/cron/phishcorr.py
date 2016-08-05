# Copyright 2016 Graeme James McGibbney

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
'''
READ in from the list of emails that are cached, deduplicate those emails that are the same
enter select from database connection everything that matches one of the emails within
the list

you will be left with a results list that can be placed within a tuple
this can then be presented within

Require the paramaters for the SQL Server 2012 database
set a print all statement after one line so that you can see
Once you get the connection variable back from the database
 Within the try statement you are trying to connect.execute (which is an SQL statement)
 which is the databse that we are trying to go to. This will need to be assigned to a
 result variable. Result variable will need to join the email addresses
 and return the email threats and then place it into elasticsearch

'''
import sqlite3
from elasticsearch import Elasticsearch,helpers

# Connect to the phishcoll database to retrieve all details on the phish that is currently stores.
# Store the phish within a list called phishList
phishconn = sqlite3.connect('phishcoll.sqlite')

cur = phishconn.cursor()
phishList = []
phishDict = {}

try:
    result = cur.execute('''SELECT Url,Target FROM Phishing_Campaigns WHERE Target != "Other"''')
    count = 0
    for item in result.fetchall():
        phishDict[count] = item
        count += 1
# phishList.append(cur.fetchall())
except sqlite3.Error as e:
    print "An error occurred whilst accessing phishcoll.sqlite database:", e.args[0]
phishconn.close()

print phishDict

emailconn = sqlite3.connect('GMData.sqlite')

cur = emailconn.cursor()
hitsList = []
count = 0

for phishAttempt in phishDict:
    try:
        cur.execute(
            '''SELECT TimeEmailReceived, RecipientAddress,
            SenderAddress FROM Email WHERE CONTAINS(EmailBodyText,'"%s" OR "%s"')''',

        )

for phishAttempt in phishList:
    try:
        cur.execute (
            '''SELECT MD.TimeReceived as [Time Email Received],
            CR.CorrespondentAddress as [Recipient Address],
            CR.CorrespondentName as [Recipient Name]
            FROM MessageBodyDetails MBD WHERE CONTAINS(MBD.BodyText,'"%s" OR "%s"')''',
            phishAttempt[count][0], phishAttempt[count][1])
        for phishHit in connmmdb.fetchall():
            combinedPhish = (phishAttempt[count][0], phishAttempt[count][1],) + phishHit
            hitsList.append(combinedPhish)
            count += 1
    except connmmdb.Error as e:
        print "An error occurred whilst accessing phishcoll.sqlite database:", e.args[0]
connmmdb.close()
# Parameter inputs need to be provided by the DBA's to connect to the
# mailmeter database: https available
connmmdb = pypyodbc.connect('Driver={SQL Server};'
                            'Server= localhost;'
                            'Database=Email_Archive;'
                            'uid=sa;pwd=P@ssw0rd')
'''
Select MD.MessageIdentity as [Email Identity],
CS.CorrespondentAddress as [Sender Address],
MD.TimeSent as [Time Email Sent],
MD.TimeReceived as [Time Email Received],
SD.SubjectText as [Email Subject],
CR.CorrespondentAddress as [Recipient Address],
CR.CorrespondentName as [Recipient Name],
MBD.BodyText as [Raw Email Body Text (Including Subject + Headers)]
From MessageBodyDetails MBD
Inner Join MessageDetails MD on MBD.BodyIdentity = MD.BodyIdentity
Inner Join MessageRecipients MR on MD.MessageIdentity = MR.MessageIdentity
Inner Join SubjectDetails SD on MD.SubjectIdentity = SD.SubjectIdentity
Inner Join CorrespondentDetails CS on MR.SenderIdentity = CS.CorrespondentIdentity
Inner Join CorrespondentDetails CR on MR.RecipientIdentity = CR.CorrespondentIdentity
Where MBD.BodyText Like '%test%'
Order By MD.TimeReceived Desc
'''


# Draft of stored procedure that needs to be used for passing the variable into the mailmeter database.
'''
USE <<name of the mailmeter database>>
GO

CREATE PROC spPhishEmail (@PhishUrl AS TEXT)
AS
BEGIN
    SELECT
        <<email address>>
        ,<<time email received>>
    FROM
        <<name of table>>
    WHERE
        table_name.the_date > DATE_SUB(CURDATE(), INTERVAL 1 DAY) AND
        <<body of email column >> LIKE '%' + @PhishUrl + '%'

END
'''
# We'll now build up a Python dictionary of our data set in a format that the
# Python ES client can use. We are going to load the data by means of bulk
# indexing. According to the Elasticsearch Bulk API docs, the body of the bulk
# index request must consist of two lines for each operation: one specifying the
# meta-data for the operation; and one specifying the actual data that it will
# index. The code below will build a dictionary that meets these requirements
# for our data:

bulk_data = []
targetList = ['Recipient Address','Recipient Name','Target','Url','Time Email Received']
for hit in hitsList:
    data_dict = {}
    count = 0
    for item in hit:
        data_dict[unicode(targetList[count])] = item
        count += 1
    op_dict = {
        "index": {
            "_index": 'threatelligence',
            "_type": 'PhishingAttacks',
            #"_id": data_dict[ID_FIELD]
        }
    }
    bulk_data.append(op_dict)
    bulk_data.append(data_dict)

# Let's create our index using the Python ES client.
# By default we assume the aserver is running on http://localhost:9200
es = Elasticsearch(hosts=['localhost:9200'])
# bulk index the data
res = es.bulk(index = 'threatelligence', body = bulk_data, refresh = True)
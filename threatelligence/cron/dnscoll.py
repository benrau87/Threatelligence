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


# Script makes a call to malware domains, collects a copy of the
# data stored on the site and then stores it into the dnscoll.sqlite database
import sqlite3
import urllib

conn = sqlite3.connect('dnscoll.sqlite')
cur = conn.cursor()

cur.execute('''
DROP TABLE IF EXISTS Collect''')

cur.execute('''
CREATE TABLE Collect (domain TEXT)''')


count = 0
fhand = urllib.urlopen('http://malwaredomains.lehigh.edu/files/justdomains')
for line in fhand:
    #print line.strip()
    count = count + 1
    cur.execute('''INSERT INTO Collect (domain) VALUES (?) ''', (line, ))

conn.commit()
print count

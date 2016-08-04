import smtplib

sender = 'threatelligence@gmail.com'

receivers = ['g.j.mcgibbney@2015.ljmu.ac.uk']

message = """ From: From ThreatIntel <test@gmail.com>
To: To InformationSecurity <g.j.mcgibbney@2015.ljmu.ac.uk>
Subject: SMTP email test

A new threat correlation have been identified
"""
smtpObj = smtplib.SMTP('smtp.gmail.com',587)
smtpObj.ehlo()
smtpObj.starttls()
smtpObj.login('threatelligence@gmail.com','')
smtpObj.sendmail(sender, receivers, message)
smtpObj.close()
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
import smtplib
from string import Template

# Send an HTML email with an embedded image and a plain text message for
# email clients that don't want to display the HTML.
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

sender = 'threatelligence@gmail.com'

receivers = 'g.j.mcgibbney@2015.ljmu.ac.uk'

class IntelNotify:
    def __init__(self):
        self.sender = 'threatelligence@gmail.com'
        self.receivers = 'g.j.mcgibbney@2015.ljmu.ac.uk'

    def get_description(self, script):
        return {
                'dnscorr.py': 'Description for dnscorr.py goes here.',
                'phishcorr.py': 'Description for phishcorr.py goes here.',
                'vulncorr.py': 'Description for vulncorr.py goes here.',
        }.get(script, 'There was an error generating a job description, please contact ' + sender) # script is default if the input not found

    def send_mail(self, correlations, time, script):
        """Simple convenience function which sends an email \
        from the configured sender to receivers.
        :param correlations: number representing the combined \
          number of threats to be reported.
        :type correlations: :mod:`int`
        :param time: the time it took for the calling program \
            to execute and finish successfully.
        :type time: :mod:`string`
        :param script: the script which was invoked such that a \
            detailed job description can be provided to correlation notifications.
        :type time: :mod:`string`
        """

        description = self.get_description(script)
        message = Template("""
        <br><img src="cid:image1" width="200"><br>
        <p>You are receiving this email because you are subscribed to <b>Assurant's Threat Intelligence notification service</b>.</p>
        <p><b>$corr threat correlation(s) have been identified</b> whilst running one of our threat correlation scripts.</p>
        <p>Identified correlations relate to: <b>$desc</b>.</p>
        <p>To view correlation(s) please visit the Kibana dashboard.</p>
        <p>Time taken to identify correlations was <b>$dur seconds</b>.</p>
        <p><i>To unsubscribe from this service please contact $sender</i>.</p>
        """)
        fullMessage = message.substitute(corr=correlations, dur=time, sender=sender, desc=description)
        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = 'Assurant Threatelligence Update'
        msgRoot['From'] = sender
        msgRoot['To'] = receivers
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)

        msgText = MIMEText('This is the alternative plain text message.')
        msgAlternative.attach(msgText)
        
        # We reference the image in the IMG SRC attribute by the ID we give it below
        #msgRoot = MIMEText()
        msgText = MIMEText(fullMessage, 'html')
        msgAlternative.attach(msgText)

        # This example assumes the image is in the current directory
        fp = open('assurant-logo.png', 'rb')
        msgImage = MIMEImage(fp.read())
        fp.close()

        # Define the image's ID as referenced above
        msgImage.add_header('Content-ID', '<image1>')
        msgRoot.attach(msgImage)

        smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
        smtpObj.ehlo()
        smtpObj.starttls()
        smtpObj.login(sender, 'TPBNGr0c8Qxhx1Qj5yRd')
        smtpObj.sendmail(sender, receivers, msgRoot.as_string())
        smtpObj.quit()

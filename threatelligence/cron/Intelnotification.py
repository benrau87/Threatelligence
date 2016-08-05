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

sender = 'threatelligence@gmail.com'

receivers = ['g.j.mcgibbney@2015.ljmu.ac.uk']


class IntelNotify:
    def __init__(self):
        self.sender = 'threatelligence@gmail.com'
        self.receivers = ['g.j.mcgibbney@2015.ljmu.ac.uk']

    def send_mail(self, correlations='0', time=''):
        """Simple convenience function which sends an email \
        from the configured sender to receivers.
        :param correlations: number representing the combined \
          number of threats to be reported.
        :type correlations: :mod:`int`
        :param time: the time it took for the calling program \
            to execute and finish successfully.
        :type time: :mod:`string`
        """
        message = Template("""" From: From ThreatIntel <test@gmail.com>
            To: To InformationSecurity <g.j.mcgibbney@2015.ljmu.ac.uk>
            Subject: SMTP email test
            Body: $corr correlation's have been identified whilst running
            one of our threat threat detection scripts.

            Time taken to make identify correlations was $dur.
            """)
        message.substitute(corr=correlations, dur=time)
        smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
        smtpObj.ehlo()
        smtpObj.starttls()
        smtpObj.login(sender, 'TPBNGr0c8Qxhx1Qj5yRd')
        smtpObj.sendmail(sender, receivers, message)
        smtpObj.close()

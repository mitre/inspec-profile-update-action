control 'SV-228408' do
  title 'The Exchange SMTP automated banner response must not reveal server details.'
  desc 'Automated connection responses occur as a result of FTP or Telnet connections when connecting to those services. They report a successful connection by greeting the connecting client and stating the name, release level, and (often) additional information regarding the responding product. While useful to the connecting client, connection responses can also be used by a third party to determine operating system or product release levels on the target server. The result can include disclosure of configuration information to third parties, paving the way for possible future attacks. For example, when querying the SMTP service on port 25, the default response looks similar to this one: 

220 exchange.mydomain.org Microsoft ESMTP MAIL Service, Version: 6.0.3790.211 ready at Wed, 2 Feb 2005 23:40:00 -0500

Changing the response to hide local configuration details reduces the attack profile of the target.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, Banner

For each Receive connector, if the value of "Banner" is not set to "220 SMTP Server Ready", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -Banner '220 SMTP Server Ready'

Note: The <IdentityName> and 220 SMTP Server Ready values must be in single quotes.

Repeat the procedures for each Receive connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30641r497020_chk'
  tag severity: 'medium'
  tag gid: 'V-228408'
  tag rid: 'SV-228408r612748_rule'
  tag stig_id: 'EX16-MB-000650'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-30626r497021_fix'
  tag 'documentable'
  tag legacy: ['SV-95459', 'V-80749']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

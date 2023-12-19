control 'SV-221258' do
  title 'The Exchange SMTP automated banner response must not reveal server details.'
  desc 'Automated connection responses occur as a result of FTP or Telnet connections when connecting to those services. They report a successful connection by greeting the connecting client and stating the name, release level, and (often) additional information about the responding product. While useful to the connecting client, connection responses can also be used by a third party to determine operating system or product release levels on the target server. The result can include disclosure of configuration information to third parties, paving the way for possible future attacks. For example, when querying the SMTP service on port 25, the default response looks similar to this one: 

220 exchange.mydomain.org Microsoft ESMTP MAIL Service, Version: 6.0.3790.211 ready at Wed, 2 Feb 2005 23:40:00 -0500

Changing the response to hide local configuration details reduces the attack profile of the target.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, Banner

If the value of "Banner" is not set to "220 SMTP Server Ready", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -Banner '220 SMTP Server Ready'

Note: The <IdentityName> and 220 SMTP Server Ready values must be in single quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22973r411900_chk'
  tag severity: 'medium'
  tag gid: 'V-221258'
  tag rid: 'SV-221258r612603_rule'
  tag stig_id: 'EX16-ED-000630'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-22962r411901_fix'
  tag 'documentable'
  tag legacy: ['SV-95307', 'V-80597']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

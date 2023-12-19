control 'SV-44054' do
  title 'SMTP automated banner response must not reveal server details.'
  desc 'Automated connection responses occur as a result of FTP or Telnet connections, when connecting to those services. They report a successful connection by greeting the connecting client, stating the name, release level, and (often) additional information regarding the responding product. While useful to the connecting client, connection responses can also be used by a third party to determine operating system (OS) or product release levels on the target server. The result can include disclosure of configuration information to third parties, paving the way for possible future attacks.   For example, when querying the SMTP service on port 25, the default response looks similar to this one: 

220 exchange.mydomain.org Microsoft ESMTP MAIL Service, Version: 6.0.3790.211 ready at Wed, 2 Feb 2005 23:40:00 -0500

Changing the response to hide local configuration details reduces the attack profile of the target.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, Banner

If the value of 'Banner' is not set to '220 SMTP Server Ready', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -Banner '220 SMTP Server Ready'"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33634'
  tag rid: 'SV-44054r1_rule'
  tag stig_id: 'Exch-2-200'
  tag gtitle: 'Exch-2-200'
  tag fix_id: 'F-37526r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end

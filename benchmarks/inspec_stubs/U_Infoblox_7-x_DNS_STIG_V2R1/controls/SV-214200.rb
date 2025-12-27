control 'SV-214200' do
  title 'The DNS server implementation must log the event and notify the system administrator when anomalies in the operation of the signed zone transfers are discovered.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights. 

If anomalies are not acted upon, security functions may fail to secure the system. 

The DNS server does not have the capability of shutting down or restarting the information system. The DNS server can be configured to generate audit records when anomalies are discovered, and the OS/NDM can then trigger notification messages to the system administrator based on the presence of those audit records.'
  desc 'check', 'Infoblox systems are capable of providing notifications via remote SYSLOG, SNMP, and SMTP.

Navigate to the "Grid" tab and select "Grid Properties".
Toggle Advanced mode, and review "Monitoring", "SNMP", "SNMP Threshold", "Email", and "Notifications" tabs. 
When complete, click "Cancel" to exit the "Properties" screen.

If no external notifications are enabled, this is a finding.'
  desc 'fix', 'Navigate to "Grid" tab and edit "Grid Properties".

Toggle Advanced mode, and review "Monitoring", "SNMP", "SNMP Threshold", "Email" and "Notifications" tab.
Configure remote SYSLOG, Email, or SNMP notifications.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15415r295863_chk'
  tag severity: 'medium'
  tag gid: 'V-214200'
  tag rid: 'SV-214200r612370_rule'
  tag stig_id: 'IDNS-7X-000660'
  tag gtitle: 'SRG-APP-000474-DNS-000073'
  tag fix_id: 'F-15413r295864_fix'
  tag 'documentable'
  tag legacy: ['SV-83085', 'V-68595']
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end

control 'SV-205223' do
  title 'The DNS server implementation must log the event and notify the system administrator when anomalies in the operation of the signed zone transfers are discovered.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights. 

If anomalies are not acted upon, security functions may fail to secure the system. 

The DNS server does not have the capability of shutting down or restarting the information system. The DNS server can be configured to generate audit records when anomalies are discovered, and the OS/NDM can then trigger notification messages to the system administrator based on the presence of those audit records.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server logs the event and notifies the system administrator when anomalies in the operation of the signed zone transfers are discovered. 

If the DNS server implementation does not log the event and notify the system administrator when anomalies in the operation of the signed zone transfers are discovered, this is a finding.'
  desc 'fix', 'Configure the DNS server to log the event and notify the system administrator when anomalies in the operation of the signed zone transfers are discovered.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5490r392582_chk'
  tag severity: 'medium'
  tag gid: 'V-205223'
  tag rid: 'SV-205223r879845_rule'
  tag stig_id: 'SRG-APP-000474-DNS-000073'
  tag gtitle: 'SRG-APP-000474'
  tag fix_id: 'F-5490r392583_fix'
  tag 'documentable'
  tag legacy: ['SV-69153', 'V-54907']
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end

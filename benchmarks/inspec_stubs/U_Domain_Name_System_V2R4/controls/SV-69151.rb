control 'SV-69151' do
  title 'The DNS server implementation must perform verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. Without verification, security functions may not operate correctly and this failure may go unnoticed. 

Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.

The DNS server should perform self-tests, such as at server start-up, to confirm that its security functions are working properly.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server performs verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days. If the DNS server does not perform this verification when needed, this is a finding.'
  desc 'fix', 'Configure the DNS server to perform verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55531r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54905'
  tag rid: 'SV-69151r1_rule'
  tag stig_id: 'SRG-APP-000473-DNS-000072'
  tag gtitle: 'SRG-APP-000473-DNS-000072'
  tag fix_id: 'F-59767r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end

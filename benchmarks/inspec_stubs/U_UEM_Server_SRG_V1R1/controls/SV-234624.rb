control 'SV-234624' do
  title 'The UEM server must alert the system administrator when anomalies in the operation of security functions are discovered.'
  desc 'If anomalies are not acted upon, security functions may fail to secure the system. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing. 

Satisfies:FAU_ALT_EXT.1.1 c.'
  desc 'check', 'Verify the UEM server alerts the system administrator when anomalies in the operation of security functions are discovered.

If the UEM server does not alert the system administrator when anomalies in the operation of security functions are discovered, this is a finding.'
  desc 'fix', 'Configure the UEM server to alert the system administrator when anomalies in the operation of security functions are discovered.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37809r616006_chk'
  tag severity: 'medium'
  tag gid: 'V-234624'
  tag rid: 'SV-234624r617355_rule'
  tag stig_id: 'SRG-APP-000474-UEM-000349'
  tag gtitle: 'SRG-APP-000474'
  tag fix_id: 'F-37774r615507_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end

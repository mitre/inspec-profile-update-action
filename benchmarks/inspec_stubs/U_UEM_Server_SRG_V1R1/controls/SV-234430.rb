control 'SV-234430' do
  title 'The application must notify the Information System Security Manager (ISSM) and Information System Security Officer (ISSO) of failed security verification tests.'
  desc 'If personnel are not notified of failed security verification tests, they will not be able to take corrective action and the unsecure condition(s) will remain. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Verify the UEM server notifies the ISSO and ISSM of failed security verification tests.

If the UEM server does not notify the ISSO and ISSM of failed security verification tests, this is a finding.'
  desc 'fix', 'Configure the UEM server to notify the ISSO and ISSM of failed security verification tests.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37615r614300_chk'
  tag severity: 'medium'
  tag gid: 'V-234430'
  tag rid: 'SV-234430r617355_rule'
  tag stig_id: 'SRG-APP-000275-UEM-000157'
  tag gtitle: 'SRG-APP-000275'
  tag fix_id: 'F-37580r614301_fix'
  tag 'documentable'
  tag cci: ['CCI-001294']
  tag nist: ['SI-6 c']
end

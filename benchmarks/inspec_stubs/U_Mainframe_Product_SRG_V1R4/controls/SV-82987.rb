control 'SV-82987' do
  title 'The Mainframe product must notify the system programmer and security administrator of failed security verification tests.'
  desc 'If personnel are not notified of failed security verification tests, they will not be able to take corrective action and the unsecure condition(s) will remain. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing.'
  desc 'check', 'Review Mainframe Product Installation instructions and settings.

If the Mainframe Product does not provide a message to the system programmer and security administrator to notify of failed security verification tests, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to notify the system programmer and security administrator of failed security verification tests.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69029r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68497'
  tag rid: 'SV-82987r1_rule'
  tag stig_id: 'SRG-APP-000275-MFP-000372'
  tag gtitle: 'SRG-APP-000275-MFP-000372'
  tag fix_id: 'F-74613r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001294']
  tag nist: ['SI-6 c']
end

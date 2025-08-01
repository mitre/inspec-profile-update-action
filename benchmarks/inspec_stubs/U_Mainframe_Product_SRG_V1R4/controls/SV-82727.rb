control 'SV-82727' do
  title 'The Mainframe Product must provide the capability for authorized users to capture, record, and log all content related to a user session.'
  desc 'Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered. 

This requirement does not apply to Mainframe Products that do not have a concept of a user session (e.g., calculator).'
  desc 'check', 'If the Mainframe Product has no function or capability for session operations, this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product does not have the capability to capture, record, and audit user sessions, this is a finding.

If the Mainframe Product does not  restrict the ability to capture, record, and audit user sessions  to system programmers or security administrators, this is a finding.

If an external security manager (ESM) is in use, examine the configuration and rules to determine if the ability  to capture, record, and audit user sessions is restricted to system programmers or security administrators. 

If it is not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to permit authorized users to capture, record, and log all content related to a user session.

If an ESM is in use, configure the rules to restrict the ability to capture, record, and audit user sessions to system programmers and security administrators.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68797r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68237'
  tag rid: 'SV-82727r1_rule'
  tag stig_id: 'SRG-APP-000093-MFP-000138'
  tag gtitle: 'SRG-APP-000093-MFP-000138'
  tag fix_id: 'F-74351r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end

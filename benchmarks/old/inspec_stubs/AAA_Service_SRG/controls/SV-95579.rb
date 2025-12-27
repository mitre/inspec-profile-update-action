control 'SV-95579' do
  title 'AAA Services must be configured to send audit records to a centralized audit server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify AAA Services are configured to send audit records to a centralized audit server.

If AAA Services are not configured to send audit records to a centralized audit server, this is a finding.'
  desc 'fix', 'Configure AAA Services to send audit records to a centralized audit server.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80605r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80869'
  tag rid: 'SV-95579r1_rule'
  tag stig_id: 'SRG-APP-000358-AAA-000280'
  tag gtitle: 'SRG-APP-000358-AAA-000280'
  tag fix_id: 'F-87723r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

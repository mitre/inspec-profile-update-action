control 'SV-203701' do
  title 'The operating system must off-load audit records onto a different system or media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify the operating system off-loads audit records onto a different system or media from the system being audited. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to off-load audit records onto a different system or media from the system being audited.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3826r375050_chk'
  tag severity: 'medium'
  tag gid: 'V-203701'
  tag rid: 'SV-203701r379693_rule'
  tag stig_id: 'SRG-OS-000342-GPOS-00133'
  tag gtitle: 'SRG-OS-000342'
  tag fix_id: 'F-3826r375051_fix'
  tag 'documentable'
  tag legacy: ['V-57247', 'SV-71507']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

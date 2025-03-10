control 'SV-207453' do
  title 'The VMM must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in VMMs with limited audit storage capacity.'
  desc 'check', 'Verify the VMM off-loads audit records onto a different system or media than the system being audited.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to off-load audit records onto a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7710r365763_chk'
  tag severity: 'medium'
  tag gid: 'V-207453'
  tag rid: 'SV-207453r854624_rule'
  tag stig_id: 'SRG-OS-000342-VMM-001230'
  tag gtitle: 'SRG-OS-000342'
  tag fix_id: 'F-7710r365764_fix'
  tag 'documentable'
  tag legacy: ['V-57107', 'SV-71367']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

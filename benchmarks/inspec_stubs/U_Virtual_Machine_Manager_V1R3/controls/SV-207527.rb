control 'SV-207527' do
  title 'The VMM must, at a minimum, off-load interconnected systems in real time and off-load standalone systems weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in VMMs with limited audit storage capacity.'
  desc 'check', 'Verify the VMM, at a minimum, off-loads interconnected systems in real time and off-loads standalone systems weekly.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to, at a minimum, off-load interconnected systems in real time and off-load standalone systems weekly.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7784r365985_chk'
  tag severity: 'medium'
  tag gid: 'V-207527'
  tag rid: 'SV-207527r854686_rule'
  tag stig_id: 'SRG-OS-000479-VMM-001990'
  tag gtitle: 'SRG-OS-000479'
  tag fix_id: 'F-7784r365986_fix'
  tag 'documentable'
  tag legacy: ['V-57355', 'SV-71615']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

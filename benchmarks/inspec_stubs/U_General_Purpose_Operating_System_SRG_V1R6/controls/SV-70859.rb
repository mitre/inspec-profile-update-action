control 'SV-70859' do
  title 'The operating system must, at a minimum, off-load audit data from interconnected systems in real time and off-load audit data from standalone systems weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify the operating system, at a minimum, off-loads interconnected systems in real time and off-loads standalone systems weekly. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to, at a minimum, off-load interconnected systems in real time and off-load standalone systems weekly.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57169r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56599'
  tag rid: 'SV-70859r2_rule'
  tag stig_id: 'SRG-OS-000479-GPOS-00224'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-61495r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

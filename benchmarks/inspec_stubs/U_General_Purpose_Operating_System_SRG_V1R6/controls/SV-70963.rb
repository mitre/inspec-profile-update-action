control 'SV-70963' do
  title 'Operating systems must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'Verify operating system enforces a 60-day maximum password lifetime restriction. If it does not, this is a finding.'
  desc 'fix', 'Configure operating system to enforce a 60-day maximum password lifetime restriction.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56703'
  tag rid: 'SV-70963r1_rule'
  tag stig_id: 'SRG-OS-000076-GPOS-00044'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-61599r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end

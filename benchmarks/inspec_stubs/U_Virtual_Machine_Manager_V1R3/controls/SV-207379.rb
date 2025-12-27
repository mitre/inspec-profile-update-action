control 'SV-207379' do
  title 'The VMM must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the VMM does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the VMM passwords could be compromised.'
  desc 'check', 'Verify the VMM enforces a 60-day maximum password lifetime restriction.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce a 60-day maximum password lifetime restriction.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7636r365547_chk'
  tag severity: 'medium'
  tag gid: 'V-207379'
  tag rid: 'SV-207379r378760_rule'
  tag stig_id: 'SRG-OS-000076-VMM-000430'
  tag gtitle: 'SRG-OS-000076'
  tag fix_id: 'F-7636r365548_fix'
  tag 'documentable'
  tag legacy: ['SV-71209', 'V-56949']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end

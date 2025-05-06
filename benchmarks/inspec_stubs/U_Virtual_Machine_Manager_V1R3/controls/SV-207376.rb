control 'SV-207376' do
  title 'The VMM must store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the VMM stores only encrypted representations of passwords.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to store only encrypted representations of passwords.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7633r365538_chk'
  tag severity: 'medium'
  tag gid: 'V-207376'
  tag rid: 'SV-207376r378751_rule'
  tag stig_id: 'SRG-OS-000073-VMM-000400'
  tag gtitle: 'SRG-OS-000073'
  tag fix_id: 'F-7633r365539_fix'
  tag 'documentable'
  tag legacy: ['V-56943', 'SV-71203']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

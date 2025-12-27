control 'SV-203629' do
  title 'The operating system must store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the operating system stores only encrypted representations of passwords. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to store only encrypted representations of passwords.'
  impact 0.7
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3754r557611_chk'
  tag severity: 'high'
  tag gid: 'V-203629'
  tag rid: 'SV-203629r877397_rule'
  tag stig_id: 'SRG-OS-000073-GPOS-00041'
  tag gtitle: 'SRG-OS-000073'
  tag fix_id: 'F-3754r557612_fix'
  tag 'documentable'
  tag legacy: ['V-56697', 'SV-70957']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

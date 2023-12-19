control 'SV-70957' do
  title 'The operating system must store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the operating system stores only encrypted representations of passwords. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to store only encrypted representations of passwords.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57267r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56697'
  tag rid: 'SV-70957r1_rule'
  tag stig_id: 'SRG-OS-000073-GPOS-00041'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-61593r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

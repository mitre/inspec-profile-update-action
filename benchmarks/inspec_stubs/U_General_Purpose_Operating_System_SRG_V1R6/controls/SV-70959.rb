control 'SV-70959' do
  title 'The operating system must transmit only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the operating system transmits only encrypted representations of passwords. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to transmit only encrypted representations of passwords.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57269r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56699'
  tag rid: 'SV-70959r1_rule'
  tag stig_id: 'SRG-OS-000074-GPOS-00042'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-61595r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end

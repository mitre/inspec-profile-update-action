control 'SV-207377' do
  title 'The VMM must transmit only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the VMM transmits only encrypted representations of passwords.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to transmit only encrypted representations of passwords.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7634r365541_chk'
  tag severity: 'medium'
  tag gid: 'V-207377'
  tag rid: 'SV-207377r378754_rule'
  tag stig_id: 'SRG-OS-000074-VMM-000410'
  tag gtitle: 'SRG-OS-000074'
  tag fix_id: 'F-7634r365542_fix'
  tag 'documentable'
  tag legacy: ['SV-71205', 'V-56945']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end

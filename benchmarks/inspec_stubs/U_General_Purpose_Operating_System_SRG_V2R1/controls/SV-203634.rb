control 'SV-203634' do
  title 'The operating system must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify the operating system enforces a minimum 15-character password length. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a minimum 15-character password length.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3759r557626_chk'
  tag severity: 'medium'
  tag gid: 'V-203634'
  tag rid: 'SV-203634r557628_rule'
  tag stig_id: 'SRG-OS-000078-GPOS-00046'
  tag gtitle: 'SRG-OS-000078'
  tag fix_id: 'F-3759r557627_fix'
  tag 'documentable'
  tag legacy: ['V-56743', 'SV-71003']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

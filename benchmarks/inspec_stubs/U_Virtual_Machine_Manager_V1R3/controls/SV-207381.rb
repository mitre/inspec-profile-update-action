control 'SV-207381' do
  title 'The VMM must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify the VMM enforces a minimum 15-character password length.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce a minimum 15-character password length.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7638r365553_chk'
  tag severity: 'medium'
  tag gid: 'V-207381'
  tag rid: 'SV-207381r378766_rule'
  tag stig_id: 'SRG-OS-000078-VMM-000450'
  tag gtitle: 'SRG-OS-000078'
  tag fix_id: 'F-7638r365554_fix'
  tag 'documentable'
  tag legacy: ['SV-71213', 'V-56953']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

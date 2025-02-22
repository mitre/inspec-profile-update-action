control 'SV-207425' do
  title 'The VMM must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Verify the VMM enforces password complexity by requiring that at least one special character be used.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce password complexity by requiring that at least one special character be used.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7682r365685_chk'
  tag severity: 'medium'
  tag gid: 'V-207425'
  tag rid: 'SV-207425r379249_rule'
  tag stig_id: 'SRG-OS-000266-VMM-000940'
  tag gtitle: 'SRG-OS-000266'
  tag fix_id: 'F-7682r365686_fix'
  tag 'documentable'
  tag legacy: ['SV-71311', 'V-57051']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end

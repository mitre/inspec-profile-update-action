control 'SV-203676' do
  title 'The operating system must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Verify the operating system enforces password complexity by requiring that at least one special character be used. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one special character be used.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3801r374915_chk'
  tag severity: 'medium'
  tag gid: 'V-203676'
  tag rid: 'SV-203676r379249_rule'
  tag stig_id: 'SRG-OS-000266-GPOS-00101'
  tag gtitle: 'SRG-OS-000266'
  tag fix_id: 'F-3801r374916_fix'
  tag 'documentable'
  tag legacy: ['SV-71447', 'V-57187']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end

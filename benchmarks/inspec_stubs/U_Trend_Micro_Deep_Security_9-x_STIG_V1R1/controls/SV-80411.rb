control 'SV-80411' do
  title 'Trend Deep Security must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure password complexity is enforced by requiring that at least one special character be used.

Verify the values for password complexity.

If the "User password requires non-alphanumeric characters" value for password complexity under the Administration >> System Settings >> Security tab has not been set, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to enforce password complexity by requiring that at least one special character be used.

Enable the checkbox for the "User password requires non-alphanumeric characters" policy value for password complexity under the Administration >> System Settings >> Security tab.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66569r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65921'
  tag rid: 'SV-80411r1_rule'
  tag stig_id: 'TMDS-00-000160'
  tag gtitle: 'SRG-APP-000169'
  tag fix_id: 'F-71997r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end

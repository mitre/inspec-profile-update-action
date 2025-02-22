control 'SV-233093' do
  title 'The container platform must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include ~ ! @ # $ % ^ *.'
  desc 'check', 'Review the container platform configuration to determine if it enforces password complexity by requiring that at least one special character be used. 

If the container platform does not enforce password complexity by requiring that at least one special character be used, this is a finding.'
  desc 'fix', 'Configure the container platform to enforce password complexity by requiring that at least one special character be used.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36029r601730_chk'
  tag severity: 'medium'
  tag gid: 'V-233093'
  tag rid: 'SV-233093r879606_rule'
  tag stig_id: 'SRG-APP-000169-CTR-000425'
  tag gtitle: 'SRG-APP-000169'
  tag fix_id: 'F-35997r600767_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end

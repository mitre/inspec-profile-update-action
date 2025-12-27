control 'SV-206472' do
  title 'The Central Log Server must be configured to enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to enforce password complexity by requiring that at least one special character be used.

If the Central Log Server is not configured to enforce password complexity by requiring that at least one special character be used, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to enforce password complexity by requiring that at least one special character be used.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6732r285660_chk'
  tag severity: 'low'
  tag gid: 'V-206472'
  tag rid: 'SV-206472r397516_rule'
  tag stig_id: 'SRG-APP-000169-AU-002520'
  tag gtitle: 'SRG-APP-000169'
  tag fix_id: 'F-6732r285661_fix'
  tag 'documentable'
  tag legacy: ['SV-96063', 'V-81349']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end

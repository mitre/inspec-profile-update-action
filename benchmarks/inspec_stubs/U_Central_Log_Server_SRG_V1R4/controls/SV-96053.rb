control 'SV-96053' do
  title 'The Central Log Server must be configured to enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to enforce password complexity by requiring that at least one lower-case character be used.

If the Central Log Server is not configured to enforce password complexity by requiring that at least one lower-case character be used, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to enforce password complexity by requiring that at least one lower-case character be used.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-81045r1_chk'
  tag severity: 'low'
  tag gid: 'V-81339'
  tag rid: 'SV-96053r1_rule'
  tag stig_id: 'SRG-APP-000167-AU-002500'
  tag gtitle: 'SRG-APP-000167-AU-002500'
  tag fix_id: 'F-88123r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end

control 'SV-206469' do
  title 'The Central Log Server must be configured to enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to enforce password complexity by requiring that at least one upper-case character be used.

If the Central Log Server is not configured to  enforce password complexity by requiring that at least one upper-case character be used, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to enforce password complexity by requiring that at least one upper-case character be used.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6729r285651_chk'
  tag severity: 'low'
  tag gid: 'V-206469'
  tag rid: 'SV-206469r397507_rule'
  tag stig_id: 'SRG-APP-000166-AU-002490'
  tag gtitle: 'SRG-APP-000166'
  tag fix_id: 'F-6729r285652_fix'
  tag 'documentable'
  tag legacy: ['SV-96051', 'V-81337']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end

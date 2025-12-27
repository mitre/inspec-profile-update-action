control 'SV-233090' do
  title 'The container platform must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Review the container platform configuration to determine if it enforces password complexity by requiring that at least one uppercase character be used. 

If the container platform does not enforce password complexity by requiring that at least one uppercase character be used, this is a finding.'
  desc 'fix', 'Configure the container platform to enforce password complexity by requiring that at least one uppercase character be used.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36026r601724_chk'
  tag severity: 'medium'
  tag gid: 'V-233090'
  tag rid: 'SV-233090r879603_rule'
  tag stig_id: 'SRG-APP-000166-CTR-000410'
  tag gtitle: 'SRG-APP-000166'
  tag fix_id: 'F-35994r600758_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end

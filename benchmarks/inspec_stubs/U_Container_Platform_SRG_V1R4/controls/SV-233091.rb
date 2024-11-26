control 'SV-233091' do
  title 'The container platform must enforce password complexity by requiring that at least one lowercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Review the container platform configuration to determine if it enforces password complexity by requiring that at least one lowercase character be used. 

If the container platform does not enforce password complexity by requiring that at least one lowercase character be used, this is a finding.'
  desc 'fix', 'Configure the container platform to enforce password complexity by requiring that at least one lowercase character be used.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36027r601726_chk'
  tag severity: 'medium'
  tag gid: 'V-233091'
  tag rid: 'SV-233091r879604_rule'
  tag stig_id: 'SRG-APP-000167-CTR-000415'
  tag gtitle: 'SRG-APP-000167'
  tag fix_id: 'F-35995r600761_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end

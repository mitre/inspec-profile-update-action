control 'SV-80407' do
  title 'Trend Deep Security must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure password complexity is enforced by requiring that at least one upper-case character be used.

Verify the values for password complexity.

If the "User password requires both upper-and lower-case characters" value for password complexity under the Administration >> System Settings >> Security tab has not been set, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to enforce password complexity by requiring that at least one uppercase character be used.

Enable the checkbox for the "User password requires both upper-and lower-case characters" policy value for password complexity under the Administration >> System Settings >> Security tab.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66565r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65917'
  tag rid: 'SV-80407r1_rule'
  tag stig_id: 'TMDS-00-000145'
  tag gtitle: 'SRG-APP-000166'
  tag fix_id: 'F-71993r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end

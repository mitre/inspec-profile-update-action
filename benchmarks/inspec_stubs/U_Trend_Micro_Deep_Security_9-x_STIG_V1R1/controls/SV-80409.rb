control 'SV-80409' do
  title 'Trend Deep Security must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure password complexity is enforced by requiring that at least one numeric character be used.

Verify the values for password complexity.

If the "User password requires both letters and numbers" value for password complexity under the Administration >> System Settings >> Security tab has not been set, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to enforce password complexity by requiring that at least one numeric character be used.

Enable the checkbox for the "User password requires both letters and numbers" policy value for password complexity under the Administration >> System Settings >> Security tab.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66567r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65919'
  tag rid: 'SV-80409r1_rule'
  tag stig_id: 'TMDS-00-000155'
  tag gtitle: 'SRG-APP-000168'
  tag fix_id: 'F-71995r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end

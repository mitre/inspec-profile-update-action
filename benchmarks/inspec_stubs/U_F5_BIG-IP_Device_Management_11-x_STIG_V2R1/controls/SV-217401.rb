control 'SV-217401' do
  title 'If multifactor authentication is not supported and passwords must be used, the BIG-IP appliance must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that enforces password complexity by requiring that at least one numeric character be used. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that enforces password complexity by requiring that at least one numeric character be used. 

If the BIG-IP appliance is not configured to use a properly configured authentication server that enforces password complexity by requiring that at least one numeric character be used, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to enforce password complexity by requiring that at least one numeric character be used.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18626r290757_chk'
  tag severity: 'medium'
  tag gid: 'V-217401'
  tag rid: 'SV-217401r557520_rule'
  tag stig_id: 'F5BI-DM-000115'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-18624r290758_fix'
  tag 'documentable'
  tag legacy: ['V-60251', 'SV-74681']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end

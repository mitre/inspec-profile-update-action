control 'SV-217399' do
  title 'If multifactor authentication is not supported and passwords must be used, the BIG-IP appliance must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that enforce password complexity by requiring that at least one upper-case character be used. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that enforces password complexity by requiring that at least one upper-case character be used. 

If the BIG-IP appliance is not configured to use a properly configured authentication server that enforces password complexity by requiring that at least one upper-case character be used, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to enforce password complexity by requiring that at least one upper-case character be used.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18624r290751_chk'
  tag severity: 'medium'
  tag gid: 'V-217399'
  tag rid: 'SV-217399r879603_rule'
  tag stig_id: 'F5BI-DM-000111'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-18622r290752_fix'
  tag 'documentable'
  tag legacy: ['SV-74679', 'V-60249']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end

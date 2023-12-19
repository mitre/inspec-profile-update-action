control 'SV-217398' do
  title 'The BIG-IP appliance must be configured to enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that enforces a minimum 15-character password length. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that enforces a minimum of 15-character password length.

If the BIG-IP appliance is not configured to use a properly configured authentication server to enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to enforce a minimum 15-character password length.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18623r290748_chk'
  tag severity: 'medium'
  tag gid: 'V-217398'
  tag rid: 'SV-217398r879601_rule'
  tag stig_id: 'F5BI-DM-000107'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-18621r290749_fix'
  tag 'documentable'
  tag legacy: ['SV-74577', 'V-60147']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

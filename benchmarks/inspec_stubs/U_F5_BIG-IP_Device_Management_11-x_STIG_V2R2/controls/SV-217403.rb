control 'SV-217403' do
  title 'If multifactor authentication is not supported and passwords must be used, the BIG-IP appliance must require that when a password is changed, the characters are changed in at least eight (8) of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that requires when a password is changed, the characters are changed in at least eight (8) of the positions within the password. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that requires when a password is changed, the characters are changed in at least eight (8) of the positions within the password. 

If the BIG-IP appliance is not configured to use a properly configured authentication server that requires when a password is changed, the characters are changed in at least eight (8) of the positions within the password, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to require when a password is changed, the characters are changed in at least eight (8) of the positions within the password.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18628r290763_chk'
  tag severity: 'medium'
  tag gid: 'V-217403'
  tag rid: 'SV-217403r879607_rule'
  tag stig_id: 'F5BI-DM-000119'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-18626r290764_fix'
  tag 'documentable'
  tag legacy: ['SV-74585', 'V-60155']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end

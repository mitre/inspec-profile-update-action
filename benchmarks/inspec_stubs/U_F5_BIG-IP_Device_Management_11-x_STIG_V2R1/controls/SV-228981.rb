control 'SV-228981' do
  title 'Upon successful logon, the BIG-IP appliance must be configured to notify the administrator of the date and time of the last logon.'
  desc 'Administrators need to be aware of activity that occurs regarding their network device management account. Providing administrators with information regarding the date and time of their last successful logon allows them to determine if any unauthorized activity has occurred. This incorporates all methods of logon, including, but not limited to, SSH, HTTP, HTTPS, and physical connectivity.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server to notify the administrator of the date and time of their last logon. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server to notify the administrator of the date and time of the last logon.

If the administrator is not notified of the date and time of the last logon upon successful logon, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved remote authentication server to notify the administrator of the date and time of the last logon upon successful logon.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31296r517990_chk'
  tag severity: 'medium'
  tag gid: 'V-228981'
  tag rid: 'SV-228981r557520_rule'
  tag stig_id: 'F5BI-DM-000037'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31273r517991_fix'
  tag 'documentable'
  tag legacy: ['V-60115', 'SV-74545']
  tag cci: ['CCI-000052', 'CCI-000366']
  tag nist: ['AC-9', 'CM-6 b']
end

control 'SV-228982' do
  title 'Upon successful logon, the BIG-IP appliance must be configured to notify the administrator of the number of unsuccessful logon attempts since the last successful logon.'
  desc 'Administrators need to be aware of activity that occurs regarding their network device management account. Providing administrators with information regarding the number of unsuccessful attempts made to logon to their account allows them to determine if any unauthorized activity has occurred. Without this information, the administrator may not be aware that unauthorized activity has occurred. This incorporates all methods of logon, including, but not limited to, SSH, HTTP, HTTPS, and physical connectivity.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server to notify the administrator of the number of unsuccessful logon attempts since the last successful logon.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server to notify the administrator of the number of unsuccessful logon attempts since the last successful logon.

If the administrator is not notified of the number of unsuccessful logon attempts since the last successful logon, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved remote authentication server to notify the administrator of the number of unsuccessful logon attempts since the last successful logon, upon successful logon.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31297r517993_chk'
  tag severity: 'medium'
  tag gid: 'V-228982'
  tag rid: 'SV-228982r557520_rule'
  tag stig_id: 'F5BI-DM-000039'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31274r517994_fix'
  tag 'documentable'
  tag legacy: ['V-60117', 'SV-74547']
  tag cci: ['CCI-000053', 'CCI-000366']
  tag nist: ['AC-9 (1)', 'CM-6 b']
end

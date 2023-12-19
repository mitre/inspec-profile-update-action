control 'SV-229009' do
  title 'The BIG-IP appliance must be configured to notify the administrator of the number of successful logon attempts occurring during an organization-defined time period.'
  desc 'Administrators need to be aware of activity that occurs regarding their network device management account. Providing administrators with information regarding the date and time of their last successful logon allows the administrator to determine if any unauthorized activity has occurred. This incorporates all methods of logon, including, but not limited to, SSH, HTTP, HTTPS, and physical connectivity. 

The organization-defined time period is dependent on the frequency with which administrators typically log on to the network device.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that notifies the administrator of the number of successful logon attempts occurring during an organization-defined time period.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that notifies the administrator of the number of successful logon attempts occurring during an organization-defined time period.

If the BIG-IP appliance is not configured to use a properly configured authentication server to notify the administrator of the number of successful logon attempts occurring during an organization-defined time period, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to notify the administrator of the number of successful logon attempts occurring during an organization-defined time period.'
  impact 0.3
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31324r518071_chk'
  tag severity: 'low'
  tag gid: 'V-229009'
  tag rid: 'SV-229009r557520_rule'
  tag stig_id: 'F5BI-DM-000261'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31301r518072_fix'
  tag 'documentable'
  tag legacy: ['SV-74653', 'V-60223']
  tag cci: ['CCI-000366', 'CCI-001391']
  tag nist: ['CM-6 b', 'AC-9 (2)']
end

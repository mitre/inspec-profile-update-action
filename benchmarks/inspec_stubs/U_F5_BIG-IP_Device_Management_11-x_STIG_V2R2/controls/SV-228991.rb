control 'SV-228991' do
  title 'The BIG-IP appliance must be configured to enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the network device does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the passwords could be compromised. 

This requirement does not include emergency administration accounts that are meant for access to the network device in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that enforces a 60-day maximum password lifetime. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that enforces a 60-day maximum password lifetime restriction. 

If the BIG-IP appliance is not configured to use a properly configured authentication server that enforces a 60-day maximum password lifetime, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance or its associated authentication server to enforce a 60-day maximum password lifetime.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31306r518018_chk'
  tag severity: 'medium'
  tag gid: 'V-228991'
  tag rid: 'SV-228991r879887_rule'
  tag stig_id: 'F5BI-DM-000127'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31283r518019_fix'
  tag 'documentable'
  tag legacy: ['V-60161', 'SV-74591']
  tag cci: ['CCI-000366', 'CCI-000199']
  tag nist: ['CM-6 b', 'IA-5 (1) (d)']
end

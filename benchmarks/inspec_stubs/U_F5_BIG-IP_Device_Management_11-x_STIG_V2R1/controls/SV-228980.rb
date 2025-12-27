control 'SV-228980' do
  title 'The BIG-IP appliance must automatically disable accounts after a 35-day period of account inactivity.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Inactive accounts could be reactivated or compromised by unauthorized users, allowing exploitation of vulnerabilities and undetected access to the network device. 

This control does not include emergency administration accounts, which are meant for access to the network device components in case of network failure.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server that automatically disables accounts after 35 days of inactivity.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that automatically disables accounts after a 35-day period of account inactivity.

If the BIG-IP appliance is not configured to use a remote authentication server that automatically disables accounts after a 35-day period of account inactivity, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved remote authentication server that automatically disables accounts after 35 days of inactivity.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31295r517987_chk'
  tag severity: 'medium'
  tag gid: 'V-228980'
  tag rid: 'SV-228980r557520_rule'
  tag stig_id: 'F5BI-DM-000017'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31272r517988_fix'
  tag 'documentable'
  tag legacy: ['V-60099', 'SV-74529']
  tag cci: ['CCI-000366', 'CCI-000017']
  tag nist: ['CM-6 b', 'AC-2 (3) (d)']
end

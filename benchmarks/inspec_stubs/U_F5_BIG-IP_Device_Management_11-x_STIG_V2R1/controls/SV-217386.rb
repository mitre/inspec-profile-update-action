control 'SV-217386' do
  title 'The BIG-IP appliance must automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server that automatically audits account removal actions. 

Verify the BIG-IP appliance is configured to use a properly configured authentication server. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured to use an approved remote authentication server that automatically audits account removal actions.

If account removal is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved authentication server that automatically audits account removal actions.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18611r290712_chk'
  tag severity: 'medium'
  tag gid: 'V-217386'
  tag rid: 'SV-217386r557520_rule'
  tag stig_id: 'F5BI-DM-000025'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-18609r290713_fix'
  tag 'documentable'
  tag legacy: ['V-60109', 'SV-74539']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end

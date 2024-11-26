control 'SV-217385' do
  title 'The BIG-IP appliance must automatically audit account-disabling actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account disabling actions will support account management procedures. When device management accounts are disabled, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server that automatically audits account-disabling actions. 

Verify the BIG-IP appliance is configured to use a properly configured authentication server. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured to use an approved remote authentication server that automatically audits account-disabling actions.

If account disabling is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved authentication server that automatically audits account-disabling actions.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18610r290709_chk'
  tag severity: 'medium'
  tag gid: 'V-217385'
  tag rid: 'SV-217385r557520_rule'
  tag stig_id: 'F5BI-DM-000023'
  tag gtitle: 'SRG-APP-000028-NDM-000210'
  tag fix_id: 'F-18608r290710_fix'
  tag 'documentable'
  tag legacy: ['V-60107', 'SV-74537']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end

control 'SV-229007' do
  title 'The BIG-IP appliance must be configured to dynamically manage user accounts.'
  desc 'Dynamic user account management prevents disruption of operations by minimizing the need for system restarts. Dynamic establishment of new user accounts will occur while the system is operational. New user accounts or changes to existing user accounts must take effect without the need for a system or session restart. Pre-established trust relationships and mechanisms with appropriate authorities (e.g., Active Directory or authentication server) that validate each user account are essential to prevent unauthorized access by changed or revoked accounts.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that dynamically manages user accounts. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that is configured to dynamically manage user accounts.

If the BIG-IP appliance is not configured to use a properly configured authentication server to dynamically manage user accounts, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to dynamically manage user accounts.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31322r518065_chk'
  tag severity: 'medium'
  tag gid: 'V-229007'
  tag rid: 'SV-229007r879887_rule'
  tag stig_id: 'F5BI-DM-000227'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31299r518066_fix'
  tag 'documentable'
  tag legacy: ['SV-74643', 'V-60213']
  tag cci: ['CCI-000366', 'CCI-001976']
  tag nist: ['CM-6 b', 'IA-4 (5)']
end

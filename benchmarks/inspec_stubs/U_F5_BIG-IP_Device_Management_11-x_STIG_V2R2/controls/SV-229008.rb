control 'SV-229008' do
  title 'The BIG-IP appliance must be configured to allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon. 

Temporary passwords are typically used to allow access to applications when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts that allow the users to log on yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use an authentication server that allows the use of a temporary password for system logons with an immediate change to a permanent password. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that allows the use of a temporary password for system logons with an immediate change to a permanent password.

If the BIG-IP appliance is not configured to authenticate through an authentication server that allows the use of a temporary password for system logons with an immediate change to a permanent password, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an authentication server that allows the use of a temporary password for system logons with an immediate change to a permanent password.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31323r518068_chk'
  tag severity: 'medium'
  tag gid: 'V-229008'
  tag rid: 'SV-229008r879887_rule'
  tag stig_id: 'F5BI-DM-000229'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31300r518069_fix'
  tag 'documentable'
  tag legacy: ['SV-74645', 'V-60215']
  tag cci: ['CCI-000366', 'CCI-002041']
  tag nist: ['CM-6 b', 'IA-5 (1) (f)']
end

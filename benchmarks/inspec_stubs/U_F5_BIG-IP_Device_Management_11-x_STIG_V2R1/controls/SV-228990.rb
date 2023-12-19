control 'SV-228990' do
  title 'The BIG-IP appliance must be configured to enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy-based intervals; however, if the network device allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that enforces 24 hours/1 day as the minimum password lifetime. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that enforces 24 hours/1 day as the minimum password lifetime. 

If the BIG-IP appliance is not configured to use a properly configured authentication server that enforces 24 hours/1 day as the minimum password lifetime, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server that enforces 24 hours/1 day as the minimum password lifetime.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31305r518015_chk'
  tag severity: 'medium'
  tag gid: 'V-228990'
  tag rid: 'SV-228990r557520_rule'
  tag stig_id: 'F5BI-DM-000125'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31282r518016_fix'
  tag 'documentable'
  tag legacy: ['SV-74683', 'V-60253']
  tag cci: ['CCI-000366', 'CCI-000198']
  tag nist: ['CM-6 b', 'IA-5 (1) (d)']
end

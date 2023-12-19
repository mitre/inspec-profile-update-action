control 'SV-228992' do
  title 'The BIG-IP appliance must be configured to automatically remove or disable emergency accounts after 72 hours.'
  desc 'Emergency accounts are administrator accounts that are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. 

If emergency accounts remain active when no longer needed, they may be used to gain unauthorized access. The risk is greater for the network device since these accounts have elevated privileges. To mitigate this risk, automated termination of all emergency accounts must be set upon account creation.

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by network administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency account is normally a different account that is created for use by vendors or system maintainers.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured remote authentication server to automatically disable or remove emergency accounts after 72 hours. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that automatically removes or disables emergency accounts after 72 hours.

If the use of emergency accounts is prohibited, this is not a finding. 

If the BIG-IP appliance is not configured to use a properly configured authentication server to automatically disable or remove emergency accounts after 72 hours, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured remote authentication server to automatically disable or remove emergency accounts after 72 hours.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31307r518021_chk'
  tag severity: 'medium'
  tag gid: 'V-228992'
  tag rid: 'SV-228992r879887_rule'
  tag stig_id: 'F5BI-DM-000149'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31284r518022_fix'
  tag 'documentable'
  tag legacy: ['SV-74601', 'V-60171']
  tag cci: ['CCI-000366', 'CCI-001682']
  tag nist: ['CM-6 b', 'AC-2 (2)']
end

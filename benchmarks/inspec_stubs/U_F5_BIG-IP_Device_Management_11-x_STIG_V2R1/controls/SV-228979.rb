control 'SV-228979' do
  title 'The BIG-IP appliance must automatically remove or disable temporary user accounts after 72 hours.'
  desc 'Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation. If temporary accounts remain active when no longer needed, they may be used to gain unauthorized access. The risk is greater for the network device since these accounts have elevated privileges. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server to automatically disable or remove temporary accounts after 72 hours.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that automatically removes or disables temporary user accounts after 72 hours.

If the use of temporary accounts is prohibited, this is not a finding. 

If the BIG-IP appliance is not configured to use a remote authentication server that automatically disables or removes temporary accounts after 72 hours, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved remote authentication server that automatically removes or disables temporary user accounts after 72 hours.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31294r517984_chk'
  tag severity: 'medium'
  tag gid: 'V-228979'
  tag rid: 'SV-228979r557520_rule'
  tag stig_id: 'F5BI-DM-000015'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31271r517985_fix'
  tag 'documentable'
  tag legacy: ['SV-74527', 'V-60097']
  tag cci: ['CCI-000366', 'CCI-000016']
  tag nist: ['CM-6 b', 'AC-2 (2)']
end

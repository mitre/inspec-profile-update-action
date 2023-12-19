control 'SV-229012' do
  title 'The BIG-IP appliance must be configured to employ automated mechanisms to centrally verify authentication settings.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server to centrally verify authentication settings.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that employs automated mechanisms to centrally verify authentication settings.

If authentication settings are not verified centrally using automated mechanisms, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved remote authentication server to employ automated mechanisms to centrally verify authentication settings.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31327r518080_chk'
  tag severity: 'medium'
  tag gid: 'V-229012'
  tag rid: 'SV-229012r557520_rule'
  tag stig_id: 'F5BI-DM-000273'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31304r518081_fix'
  tag 'documentable'
  tag legacy: ['V-60231', 'SV-74661']
  tag cci: ['CCI-000366', 'CCI-000372']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end

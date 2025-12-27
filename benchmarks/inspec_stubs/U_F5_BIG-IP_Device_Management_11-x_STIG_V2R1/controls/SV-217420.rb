control 'SV-217420' do
  title 'The BIG-IP appliance must be configured to employ automated mechanisms to centrally manage authentication settings.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server to centrally manage authentication settings.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that employs automated mechanisms to centrally manage authentication settings.

If authentication settings are not managed centrally using automated mechanisms, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved remote authentication server to employ automated mechanisms to centrally manage authentication settings.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18645r290814_chk'
  tag severity: 'medium'
  tag gid: 'V-217420'
  tag rid: 'SV-217420r557520_rule'
  tag stig_id: 'F5BI-DM-000269'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-18643r290815_fix'
  tag 'documentable'
  tag legacy: ['V-60227', 'SV-74657']
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end

control 'SV-228997' do
  title 'The BIG-IP appliance must be configured to generate alerts that can be forwarded to the administrators and Information System Security Officer (ISSO) when accounts are disabled.'
  desc 'When application accounts are disabled, administrator accessibility is affected. Accounts are utilized for identifying individual device administrators or for identifying the device processes themselves. 

In order to detect and respond to events that affect administrator accessibility and device processing, devices must audit account-disabling actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that device accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that generates alerts that can be forwarded to the administrators and ISSO when accounts are disabled. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that generates alerts that can be forwarded to the administrators and ISSO when accounts are disabled.

If the BIG-IP appliance is not configured to use an authentication server that would perform this function, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to send a notification message to the administrators and ISSO when accounts are disabled.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31312r518036_chk'
  tag severity: 'medium'
  tag gid: 'V-228997'
  tag rid: 'SV-228997r879887_rule'
  tag stig_id: 'F5BI-DM-000159'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31289r518037_fix'
  tag 'documentable'
  tag legacy: ['SV-74611', 'V-60181']
  tag cci: ['CCI-000366', 'CCI-001685']
  tag nist: ['CM-6 b', 'AC-2 (4)']
end

control 'SV-229006' do
  title 'The BIG-IP appliance must be configured to implement automated security responses if baseline configurations are changed in an unauthorized manner.'
  desc 'Unauthorized changes to the baseline configuration could make the device vulnerable to various attacks or allow unauthorized access to the device. Changes to device configurations can have unintended side effects, some of which may be relevant to security. 

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the device. Examples of security responses include, but are not limited to, the following: halting application processing; halting selected functions; or issuing alerts/notifications to organizational personnel when there is an unauthorized modification of a configuration item. The appropriate automated security response may vary depending on the nature of the baseline configuration change, the role of the network device, the availability of organizational personnel to respond to alerts, etc.'
  desc 'check', 'Verify the BIG-IP appliance is configured to implement automated security responses if baseline configurations are changed in an unauthorized manner. 

Navigate to the BIG-IP System manager >> Logs >> Configuration >> Options.

Review configuration in the "Audit Logging" section.

Verify that "MCP" is set to Debug.

If the BIG-IP appliance is not configured to implement automated security responses if baseline configurations are changed in an unauthorized manner, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to implement automated security responses if baseline configurations are changed in an unauthorized manner.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31321r518062_chk'
  tag severity: 'medium'
  tag gid: 'V-229006'
  tag rid: 'SV-229006r557520_rule'
  tag stig_id: 'F5BI-DM-000211'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31298r518063_fix'
  tag 'documentable'
  tag legacy: ['SV-74637', 'V-60207']
  tag cci: ['CCI-000366', 'CCI-001744']
  tag nist: ['CM-6 b', 'CM-3 (5)']
end

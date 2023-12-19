control 'SV-217408' do
  title 'The BIG-IP appliance must be configured to terminate all management sessions after 10 minutes of inactivity.'
  desc 'If a device management session or connection remains open after management is completed, it may be hijacked by an attacker and used to compromise or damage the network device.

Nonlocal device management and diagnostic activities are activities conducted by individuals communicating through an external network (e.g., the internet) or an internal network. 

If the remote node has abnormally terminated or an upstream link from the managed device is down, BIG IP F5 terminates the management session and associated connection by default, and this is not configurable.'
  desc 'check', 'Verify the BIG-IP appliance is configured to terminate all sessions and network connections when nonlocal device maintenance is completed. 

Navigate to the BIG-IP System manager >> System >> Preferences.

Verify "Idle Time Before Automatic Logout" is set to 900 seconds (or less) and "Enforce Idle Timeout While View Dashboard" is enabled.

If the BIG-IP appliance is not configured to terminate all idle sessions after 10 minutes or less, this is a finding.'
  desc 'fix', 'Verify the BIG-IP appliance is configured to terminate all sessions and network connections when nonlocal device maintenance is completed. 

Navigate to the BIG-IP System manager >> System >> Preferences.

Verify "Idle Time Before Automatic Logout" is set to 900 seconds (or less) and "Enforce Idle Timeout While View Dashboard" is enabled.

If the BIG-IP appliance is not configured to terminate all idle sessions after 10 minutes or less, this is a finding.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18633r939112_chk'
  tag severity: 'high'
  tag gid: 'V-217408'
  tag rid: 'SV-217408r939114_rule'
  tag stig_id: 'F5BI-DM-000137'
  tag gtitle: 'SRG-APP-000186-NDM-000266'
  tag fix_id: 'F-18631r939113_fix'
  tag 'documentable'
  tag legacy: ['SV-74595', 'V-60165']
  tag cci: ['CCI-000879', 'CCI-000057', 'CCI-001133']
  tag nist: ['MA-4 e', 'AC-11 a', 'SC-10']
end

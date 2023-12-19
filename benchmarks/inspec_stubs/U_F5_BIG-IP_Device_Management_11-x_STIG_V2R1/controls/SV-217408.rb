control 'SV-217408' do
  title 'The BIG-IP appliance must be configured to terminate all sessions and network connections when nonlocal device maintenance is completed.'
  desc 'If a device management session or connection remains open after management is completed, it may be hijacked by an attacker and used to compromise or damage the network device.

Nonlocal device management and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

In the event the remote node has abnormally terminated or an upstream link from the managed device is down, the management session will be terminated, thereby freeing device resources and eliminating any possibility of an unauthorized user being orphaned to an open idle session of the managed device.'
  desc 'check', 'Verify the BIG-IP appliance is configured to terminate all sessions and network connections when nonlocal device maintenance is completed. 

Navigate to the BIG-IP System manager >> System >> Preferences.

Verify that "Idle Time Before Automatic Logout" is set to 10 minutes or less.

If the BIG-IP appliance is not configured to terminate all sessions and network connections when nonlocal device maintenance is complete, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to terminate all sessions and network connections when nonlocal device maintenance is completed.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18633r290778_chk'
  tag severity: 'medium'
  tag gid: 'V-217408'
  tag rid: 'SV-217408r557520_rule'
  tag stig_id: 'F5BI-DM-000137'
  tag gtitle: 'SRG-APP-000186-NDM-000266'
  tag fix_id: 'F-18631r290779_fix'
  tag 'documentable'
  tag legacy: ['V-60165', 'SV-74595']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end

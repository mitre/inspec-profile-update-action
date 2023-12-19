control 'SV-89649' do
  title 'The WebGUI of the MQ Appliance network device must terminate all sessions and network connections when nonlocal device maintenance is completed.'
  desc 'If an MQ Appliance device management session or connection remains open after management is completed, it may be hijacked by an attacker and used to compromise or damage the MQ Appliance network device. 

Nonlocal MQ Appliance device management and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

In the event the remote node has abnormally terminated or an upstream link from the managed device is down, the management session will be terminated, thereby freeing device resources and eliminating any possibility of an unauthorized user being orphaned to an open idle session of the managed device.'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
web-mgmt 
show 

If the idle-timeout value is not 600 seconds or less, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
web-mgmt 
idle-timeout <600 seconds or less> 
exit 
write mem 
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74827r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74975'
  tag rid: 'SV-89649r1_rule'
  tag stig_id: 'MQMH-ND-000730'
  tag gtitle: 'SRG-APP-000186-NDM-000266'
  tag fix_id: 'F-81591r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end

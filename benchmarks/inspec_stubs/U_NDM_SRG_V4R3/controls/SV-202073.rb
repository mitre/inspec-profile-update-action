control 'SV-202073' do
  title 'The network device must terminate all sessions and network connections when nonlocal device maintenance is completed.'
  desc 'If a device management session or connection remains open after management is completed, it may be hijacked by an attacker and used to compromise or damage the network device.

Nonlocal device management and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

In the event the remote node has abnormally terminated or an upstream link from the managed device is down, the management session will be terminated, thereby freeing device resources and eliminating any possibility of an unauthorized user being orphaned to an open idle session of the managed device.'
  desc 'check', 'Determine if the network device terminates all sessions and network connections when nonlocal device maintenance is completed.  This requirement may be verified by demonstration or validated test results. If the network device does not terminate all sessions and network connections when nonlocal device maintenance is complete, this is a finding.'
  desc 'fix', 'Configure the network device to terminate all sessions and network connections when nonlocal device maintenance is completed.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2199r381839_chk'
  tag severity: 'medium'
  tag gid: 'V-202073'
  tag rid: 'SV-202073r879621_rule'
  tag stig_id: 'SRG-APP-000186-NDM-000266'
  tag gtitle: 'SRG-APP-000186'
  tag fix_id: 'F-2200r381840_fix'
  tag 'documentable'
  tag legacy: ['SV-69401', 'V-55155']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end

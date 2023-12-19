control 'SV-253912' do
  title 'The Juniper EX switch must be configured to terminate all sessions and network connections when nonlocal device maintenance is completed.'
  desc 'If a device management session or connection remains open after management is completed, it may be hijacked by an attacker and used to compromise or damage the network device.

Nonlocal device management and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. 

In the event the remote node has abnormally terminated or an upstream link from the managed device is down, the management session will be terminated, thereby freeing device resources and eliminating any possibility of an unauthorized user being orphaned to an open idle session of the managed device.'
  desc 'check', 'Determine if the network device terminates all sessions and network connections when nonlocal device maintenance is completed. This requirement may be verified by demonstration or validated test results. 

Junos permits the administrator to log out after completing nonlocal maintenance, which terminates the session and the network connection. Junos forcibly terminates the session and network connection if the idle-timeout value expires or when the permissible number of missed keepalive messages is reached. Verify the number of keepalive messages and the interval between messages is appropriate. For example, to forcibly disconnect a session after 30 seconds of lost connectivity:

[edit system services ssh]
:
client-alive-count-max 3;
client-alive-interval 10;
Note: Administrator inactivity timeouts not shown because these are a separate check.

If the network device does not terminate all sessions and network connections when nonlocal device maintenance is complete, this is a finding.'
  desc 'fix', 'Configure the network device to terminate all sessions and network connections when nonlocal device maintenance is completed.

set system services ssh client-alive-count-max <0..255>
set system services ssh client-alive-interval <0..65535 seconds>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57364r843767_chk'
  tag severity: 'medium'
  tag gid: 'V-253912'
  tag rid: 'SV-253912r843769_rule'
  tag stig_id: 'JUEX-NM-000350'
  tag gtitle: 'SRG-APP-000186-NDM-000266'
  tag fix_id: 'F-57315r843768_fix'
  tag 'documentable'
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end

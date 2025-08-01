control 'SV-234213' do
  title 'The FortiGate device must terminate idle sessions after 10 minutes of inactivity.'
  desc 'If a device management session or connection remains open after management is completed, it may be hijacked by an attacker and used to compromise or damage the network device.

Nonlocal device management and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. 

In the event the remote node has abnormally terminated or an upstream link from the managed device is down, the management session will be terminated, thereby freeing device resources and eliminating any possibility of an unauthorized user being orphaned to an open idle session of the managed device.'
  desc 'check', 'Verify the FortiGate device terminates all network connections when non-local device maintenance is complete.

Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Go to Administrative Settings.
4. Verify Idle Timeout is configured to 10 minutes.

If the idle-timeout value is not 10 minutes, this is a finding.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration sys global | grep -i admintimeout

The output should be:         
          set admintimeout 10

If the admintimeout parameter is not set to 10 minutes, this is a finding.'
  desc 'fix', 'To configure the device to terminate all network connections when non-local maintenance is complete:

Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Go to Administrative Settings.
4. Enter the Idle Timeout value of 10.
5. Click Apply.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system global
          # set admintimeout 10
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37398r611826_chk'
  tag severity: 'medium'
  tag gid: 'V-234213'
  tag rid: 'SV-234213r611828_rule'
  tag stig_id: 'FGFW-ND-000270'
  tag gtitle: 'SRG-APP-000186-NDM-000266'
  tag fix_id: 'F-37363r611827_fix'
  tag 'documentable'
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end

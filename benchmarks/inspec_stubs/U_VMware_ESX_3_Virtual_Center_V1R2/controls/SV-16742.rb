control 'SV-16742' do
  title 'Notify Switches feature is not enabled to allowfor notifications to be sent to physical switches.'
  desc 'One option in NIC Teaming is Notify Switches. Whenever a virtual NIC is connected to a virtual switch or whenever a virtual NIC’s traffic would be routed over a different physical NIC due to a failover event, a notification is sent. This notification is sent out over the network to update the lookup tables on physical switches. Configuring this to ’Yes’ sends out these notifications while providing the lowest latency of failover occurrences and migrations with VMotion.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
    The hardware configuration page for the server appears.
2. Click the Configuration tab, and click Networking.
3. Select a vSwitch and click Properties.
4. In the vSwitch Properties dialog box, click the Ports tab.
5. Select the vSwitch and click Edit.
6. Click the NIC Teaming tab.
7. Verify that Notify Switches is set to “Yes”.  If not, this is a finding.'
  desc 'fix', 'Enable Notify Switches feature to allow for notifications to be send to physical switches.'
  impact 0.3
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16021r1_chk'
  tag severity: 'low'
  tag gid: 'V-15803'
  tag rid: 'SV-16742r1_rule'
  tag stig_id: 'ESX0140'
  tag gtitle: 'Notify switches features is not enabled.'
  tag fix_id: 'F-15746r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end

control 'SV-234159' do
  title 'The FortiGate firewall must allow authorized users to record a packet-capture-based IP, traffic type (TCP, UDP, or ICMP), or protocol.'
  desc 'Without the ability to capture, record, and log content related to a user session, investigations into suspicious user activity would be hampered.

This configuration ensures the ability to select specific sessions to capture in order to support general auditing/incident investigation or to validate suspected misuse.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Network.
2. Click Packet Capture.
3. Verify different Packet Capture Filters are configured and that capture packets based on interface, host, VLAN, or protocol.

If FortiGate does not allow an authorized administrator to capture packets based on interface, host, VLAN, or protocol, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

Create a Packet Capture Filter 
1. Click Network.
2. Click Packet Capture.
3. Click +Create New.
4. Select an interface from the drop down menu.
5. Specify the maximum number of packets to capture.
6. Enable Filters to configure filtering based upon Host (addresses), Port, VLAN, or Protocol.
7. Click OK.

Then, 
1. Select a packet filter from the list of packet capture filters.
2. Right-click on the selected filter.
3. Click Start.
4. Click OK.
The packet capture continues until either the configured number of packets is reached, or the administrator stops the packet capture. The administrator must download the packet capture for viewing with an external application, like Wireshark or tcpdump.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37344r611475_chk'
  tag severity: 'medium'
  tag gid: 'V-234159'
  tag rid: 'SV-234159r611477_rule'
  tag stig_id: 'FNFG-FW-000155'
  tag gtitle: 'SRG-NET-000399-FW-000008'
  tag fix_id: 'F-37309r611476_fix'
  tag 'documentable'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end

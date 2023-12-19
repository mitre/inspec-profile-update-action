control 'SV-77427' do
  title 'Riverbed Optimization System (RiOS) must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', %q(Verify that RiOS is configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions.

Navigate to the device CLI
Type: enable
Type: show ntp all
Verify that at least two NTP Servers are configured

-- or --

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Date and Time
Verify that at least two servers are configured in the section "Requested Servers"

If no NTP Servers are visible after the command 'show ntp all' or on "Requested Servers", this is a finding.)
  desc 'fix', 'Configure RiOS to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions.

Navigate to the device CLI
Type: enable
Type: conf t
Type: ntp server <hostname | ip address>
Type: ntp server <hostname | ip address> enable
Configure 2 NTP Servers
Type: ntp enable
Type: write memory

-- or --

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Date and Time
Click "Add a New NTP Server"
Set the value of "Hostname or IP Address" to the required NTP Server
Set the value of "Enabled/Disabled" to "Enabled"
Click "Add"
Configure 2 NTP Servers
Click "Use NTP Time Synchronization"

Click "Apply"
Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63689r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62937'
  tag rid: 'SV-77427r1_rule'
  tag stig_id: 'RICX-DM-000082'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-68855r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

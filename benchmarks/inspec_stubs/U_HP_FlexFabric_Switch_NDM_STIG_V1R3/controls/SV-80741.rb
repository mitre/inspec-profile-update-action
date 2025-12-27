control 'SV-80741' do
  title 'The HP FlexFabric Switch must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The HP FlexFabric Switch must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Determine if the HP FlexFabric Switch is configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.

[HP] display ntp status

 Clock status: synchronized
 Clock stratum: 4
 System peer: 16.110.135.123
 Local mode: client
 Reference clock ID: 16.110.135.123
 Leap indicator: 00
 Clock jitter: 0.004227 s
 Stability: 0.000 pps
 Clock precision: 2^-19
 Root delay: 96.75598 ms
 Root dispersion: 149.76501 ms
 Reference time: d916fabd.a5c6d326  Mon, Jun  1 2015  9:37:33.647

If the HP FlexFabric Switch is not configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources:

[HP] ntp service enable
[HP] ntp service unicast-server 16.110.135.123
[HP] ntp service unicast-server 16.110.135.124'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66897r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66251'
  tag rid: 'SV-80741r1_rule'
  tag stig_id: 'HFFS-ND-000100'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-72327r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

control 'SV-246936' do
  title 'ONTAP must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Use "cluster time-service ntp server show" to see the current network time protocol configuration for ONTAP and ensure there are at least three ntp servers defined.

If ONTAP is not configured to synchronize internal information system clocks using redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Configure network time protocol for ONTAP with "cluster time-service ntp server create -server <IP address>" to add new ntp servers. Up to 10 servers can be defined.'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50368r860678_chk'
  tag severity: 'medium'
  tag gid: 'V-246936'
  tag rid: 'SV-246936r877998_rule'
  tag stig_id: 'NAOT-AU-000004'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-50322r860679_fix'
  tag 'documentable'
  tag cci: ['CCI-001893']
  tag nist: ['AU-8 (2)']
end

control 'SV-243188' do
  title 'The network device must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must use an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Review the configuration and verify the network device synchronizes internal information system clocks using redundant authoritative time sources.

If the device is not configured to synchronize internal information system clocks using redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Configure the device to synchronize internal information system clocks using redundant authoritative time sources.'
  impact 0.5
  ref 'DPMS Target Network WLAN Bridge Mgmt'
  tag check_id: 'C-46463r720017_chk'
  tag severity: 'medium'
  tag gid: 'V-243188'
  tag rid: 'SV-243188r879746_rule'
  tag stig_id: 'WLAN-ND-001900'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-46420r720018_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

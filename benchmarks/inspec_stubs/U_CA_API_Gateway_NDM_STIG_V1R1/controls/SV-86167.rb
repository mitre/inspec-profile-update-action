control 'SV-86167' do
  title 'The CA API Gateway must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Verify the Gateway (using "ssgconfig") is configured to use multiple ntp sources using menu: 1) Configure system settings >> 1) Configure networking and system time settings. 

Walk through the query process until being queried for time servers and verify the list of ntp servers is correct.

If the CA API Gateway is not configured to use multiple ntp sources, this is a finding.'
  desc 'fix', 'Configure the Gateway using "ssgconfig" to set multiple ntp sources using menu: 1) Configure system settings >> 1) Configure networking and system time settings. 

Walk through the query process until being queried for time servers and insert a comma-separated list of ntp time servers.'
  impact 0.3
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71915r1_chk'
  tag severity: 'low'
  tag gid: 'V-71543'
  tag rid: 'SV-86167r1_rule'
  tag stig_id: 'CAGW-DM-000220'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-77863r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

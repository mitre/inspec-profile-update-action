control 'SV-217414' do
  title 'The BIG-IP appliance must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region from the primary time source.'
  desc 'check', 'Determine if the BIG-IP appliance is configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources. 

Navigate to the BIG-IP System manager >> Configuration >> Device >> NTP.

Verify there is a primary time source and a secondary time source configured that are in different geographic regions.

If the BIG-IP appliance is not configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18639r290796_chk'
  tag severity: 'medium'
  tag gid: 'V-217414'
  tag rid: 'SV-217414r879746_rule'
  tag stig_id: 'F5BI-DM-000201'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-18637r290797_fix'
  tag 'documentable'
  tag legacy: ['SV-74635', 'V-60205']
  tag cci: ['CCI-001893', 'CCI-000366']
  tag nist: ['AU-8 (2)', 'CM-6 b']
end

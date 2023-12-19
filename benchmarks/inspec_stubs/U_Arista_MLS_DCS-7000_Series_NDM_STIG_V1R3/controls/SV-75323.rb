control 'SV-75323' do
  title 'The Arista Multilayer Switch must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Determine if the network device is configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.

If the network device is not configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.

Verify with: 

switch#show NTP status 

Identify the NTP status and available time sources.'
  desc 'fix', 'Configure the network device to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.

Configuration Example: 

switch(config)#ntp server HOST
switch(config)#ntp server HOST prefer'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60865'
  tag rid: 'SV-75323r1_rule'
  tag stig_id: 'AMLS-NM-000280'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-66577r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

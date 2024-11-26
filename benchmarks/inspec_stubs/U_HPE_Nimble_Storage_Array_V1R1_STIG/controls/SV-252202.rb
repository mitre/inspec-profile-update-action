control 'SV-252202' do
  title 'The HPE Nimble must be configured to synchronize internal information system clocks using an authoritative time source.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'To Determine if the HPE Nimble Array is configured to synchronize internal information system clocks with the primary NTP server:
 
ArrayA:/# ntpq
ntpq> sysinfo
associd=0 status=0615 leap_none, sync_ntp, 1 event, clock_sync,
system peer: cxo-nmbldc-01.nimblestorage.com:123
system peer mode: client
leap indicator: 00
stratum: 4
log2 precision: -24
root delay: 37.321
root dispersion: 265.639
reference ID: 10.157.24.95
reference time: e509b178.9f897118 Thu, Oct 7 2021 11:48:40.623
system jitter: 0.000000
clock jitter: 0.673
clock wander: 0.003
broadcast delay: -50.000
symm. auth. delay: 0.000

If the HPE Storage Array is not configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Configure the HPE Nimble Array to synchronize internal information system clocks with the primary time source:
 
ArrayA:/# group --edit --ntpserver <ip_address_of_ntp_server>
  
There would be a finding here given we only support primary ntp source.'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55658r814093_chk'
  tag severity: 'medium'
  tag gid: 'V-252202'
  tag rid: 'SV-252202r814094_rule'
  tag stig_id: 'HPEN-NM-000271'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-55608r814085_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

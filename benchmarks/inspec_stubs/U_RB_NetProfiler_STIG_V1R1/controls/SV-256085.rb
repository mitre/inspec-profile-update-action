control 'SV-256085' do
  title 'The Riverbed NetProfiler must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must use an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DOD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DOD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Go to Administration >> General Settings. 

Under "Time Configuration", verify that at least the IP address for both Server 1 and Server 2 has been configured. 

If redundant time servers have not been configured, this is a finding.'
  desc 'fix', 'Go to Administration >> General Settings. 

Under "Time Configuration", configure the IP address for at least both Server 1 and Server 2. 

Select the type of encryption and configure both the key and index for each of the server entries.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59759r882761_chk'
  tag severity: 'medium'
  tag gid: 'V-256085'
  tag rid: 'SV-256085r882763_rule'
  tag stig_id: 'RINP-DM-000047'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-59702r882762_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

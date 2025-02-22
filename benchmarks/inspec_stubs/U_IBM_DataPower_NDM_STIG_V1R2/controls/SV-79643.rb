control 'SV-79643' do
  title 'The DataPower Gateway must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Using the DataPower web interface, go to Network >> Interface >> NTP Service. Confirm that the Administrative state is enabled, NTP Servers are configured, and that the Refresh Interval is set to 2040 seconds or less. If it is not, this is a finding.'
  desc 'fix', 'In the DataPower WebGUI, go to Network >> Interface >> NTP Service. Specify the IP addresses of several approved NTP servers. The refresh interval may be defined at any value between 60 and 86400 seconds.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65153'
  tag rid: 'SV-79643r1_rule'
  tag stig_id: 'WSDP-NM-000100'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-71093r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

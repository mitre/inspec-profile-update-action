control 'SV-82571' do
  title 'The A10 Networks ADC must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Review the device configuration.

The following command shows the configuration with an output modifier to display only NTP-related configuration:
show run | include ntp

Alternately, enter the command to display the configured NTP servers and whether or not NTP is enabled:
show ntp servers

If the output shows fewer than two configured NTP servers, this is a finding.

Ask the device administrator where the Primary NTP Server and Secondary NTP Server are located. 

If they are not in different geographic regions, this is a finding.'
  desc 'fix', 'Up to four NTP servers can be configured. The following commands set the NTP server and enable the Network Time Protocol:
ntp server [hostname | ipaddr]
ntp enable

Note: The primary and secondary time sources must be located in different geographic regions.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68641r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68081'
  tag rid: 'SV-82571r1_rule'
  tag stig_id: 'AADC-NM-000101'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-74197r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

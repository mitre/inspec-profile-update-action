control 'SV-242246' do
  title 'The TippingPoint SMS must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'In the SMS client, ensure two NTP sources are configured. 

1. Select Admin, Server Properties, and Network.
2. If Enable NTP is not checked or at least two NTP servers are not configured under Date/Time, this is a finding.'
  desc 'fix', 'In the SMS client, ensure two NTP sources are configured. 

1. Select Admin, Server Properties, and Network.
2. Check Enable NTP. 
3. Enter a server IPv4 address in NTP Server 1 and NTP Server.
4. Ensure this is done under an approved change window as it will cause a reboot.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45521r710743_chk'
  tag severity: 'medium'
  tag gid: 'V-242246'
  tag rid: 'SV-242246r710745_rule'
  tag stig_id: 'TIPP-NM-000400'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-45479r710744_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

control 'SV-230944' do
  title 'Forescout must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while the source synchronizes time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', %q(Determine if Forescout is configured to synchronize internal clocks with the organization's primary and secondary NTP servers.

1. Open an SSH session and authenticate to the Forescout command line.
2. Verify a primary and secondary NTP server has been configured with the command "fstool ntp test".

If Forescout is not configured to synchronize internal information system clocks with the organization's primary and secondary NTP servers, this is a finding.)
  desc 'fix', 'Configure Forescout to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.

1. Open an SSH session and authenticate to the Forescout command line.
2. Configure the primary and secondary NTP servers with the command "fstool ntp setup <ip address>".'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33874r603671_chk'
  tag severity: 'medium'
  tag gid: 'V-230944'
  tag rid: 'SV-230944r615886_rule'
  tag stig_id: 'FORE-NM-000160'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-33847r603672_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

control 'SV-90929' do
  title 'CounterACT must be configured to synchronize internal information system clocks with the organizations primary and secondary NTP servers.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. CounterACT appliances must use an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', %q(Determine if CounterACT is configured to synchronize internal clocks with the organization's primary and secondary NTP servers.

1. Open an SSH session and authenticate to the CounterACT command line.
2. Verify a primary and secondary NTP server has been configured with the command "fstool ntp".

If CounterACT is not configured to synchronize internal information system clocks with the organization's primary and secondary NTP servers, this is a finding.)
  desc 'fix', 'Configure CounterACT to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.

1. Open an SSH session and authenticate to the CounterACT command line.
2. Configure the primary and secondary NTP servers with the command "fstool ntp setup <ip address>".'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75927r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76241'
  tag rid: 'SV-90929r1_rule'
  tag stig_id: 'CACT-NM-000038'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-82877r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

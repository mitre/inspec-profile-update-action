control 'SV-104503' do
  title 'Symantec ProxySG must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Verify the Symantec ProxySG is configured to use authoritative NTP servers.

1. Log on to the Web Management Console.
2. Click Configuration >> General >> Clock.
3. Click "NTP", and confirm that the desired authoritative time servers are present.

If Symantec ProxySG does not be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Configure the ProxySG is configured to use authoritative NTP servers.

1. Log on to the Web Management Console.
2. Click Configuration >> General >> Clock.
3. Click "NTP", click "New", click "Add" and enter each desired authoritative time server.
4. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94673'
  tag rid: 'SV-104503r1_rule'
  tag stig_id: 'SYMP-NM-000110'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-100791r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

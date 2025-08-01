control 'SV-88719' do
  title 'The Cisco IOS XE router must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Verify that at least two NTP servers are configured and that system clocks update the time every 24 hours.

The configuration should look similar to the example below:

ntp authentication-key 1 md5 072C285F4D06 7
ntp authenticate
ntp trusted-key 1
ntp server 1.1.1.1 key 1
ntp server 2.2.2.2 key 1

If there are not at least two NTP servers configured, and clocks are updated at least every 24 hours, this is a finding.'
  desc 'fix', 'Configure the router to use NTP.

The configuration should look similar to the example below:

ntp authentication-key 1 md5 072C285F4D06 7
ntp authenticate
ntp trusted-key 1
ntp server 1.1.1.1 key 1
ntp server 2.2.2.2 key 1'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74135r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74045'
  tag rid: 'SV-88719r2_rule'
  tag stig_id: 'CISR-ND-000102'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-80587r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end

control 'SV-85121' do
  title 'The storage system must, for networked systems, compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'Verify NTP is operational by entering the following command:

cli% shownet 
< multiple lines of heading, and node network information>
NTP server : <ip address of ntp server>

If one of the lines of the output does not show the correct NTP server IP address, this is a finding.'
  desc 'fix', 'Enable NTP on the system by entering the following command:

cli% setnet ntp <server_addr>'
  impact 0.3
  ref 'DPMS Target HPE 3PAR OS 3.2.2'
  tag check_id: 'C-70899r1_chk'
  tag severity: 'low'
  tag gid: 'V-70499'
  tag rid: 'SV-85121r1_rule'
  tag stig_id: 'HP3P-32-001400'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-76737r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end

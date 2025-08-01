control 'SV-255277' do
  title 'The HPE 3PAR OS must, for networked systems, compare internal information system clocks at least every 24 hours with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

The HPE 3PAR OS maintains an internal synchronization of node clocks, and aligns that with an NTP client always running on the network owner node when configured as shown.'
  desc 'check', 'Verify NTP is operational:
cli% shownet

If any of the NTP Server lines in the output show an incorrect NTP Server address, this is a finding.

If only one NTP Server line is present, and it indicates "None" for the address, this is a finding.'
  desc 'fix', 'Enable NTP with:

cli% setnet ntp -add <server ip address>

This command can be used multiple times to specify multiple NTP Servers.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58950r870148_chk'
  tag severity: 'medium'
  tag gid: 'V-255277'
  tag rid: 'SV-255277r870150_rule'
  tag stig_id: 'HP3P-33-001400'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-58894r870149_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end

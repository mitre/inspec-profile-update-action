control 'SV-214838' do
  title 'The macOS system must, for networked systems, compare internal information system clocks at least every 24 hours with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet) and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. 

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

'
  desc 'check', 'The Network Time Protocol (NTP) service must be enabled on all networked systems. To check if the service is running, use the following command:

/usr/bin/sudo /bin/launchctl list | grep com.apple.timed

83	0	com.apple.timed

If nothing is returned, this is a finding.

To verify that an authorized NTP server is configured, run the following command or examine "/etc/ntp.conf":

/usr/bin/sudo /usr/bin/grep ^server /etc/ntp.conf
server ntp.usno.navy.mil
server ntp.usnogps.navy.mil

Note: Only approved time servers should be configured for use.

If no server is configured, or if an unapproved time server is in use, this is a finding.'
  desc 'fix', 'To enable the NTP service, run the following command:

/usr/bin/sudo /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist

To configure one or more time servers for use, edit "/etc/ntp.conf" and enter each hostname or IP address on a separate line, prefixing each one with the keyword "server".'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16038r466225_chk'
  tag severity: 'medium'
  tag gid: 'V-214838'
  tag rid: 'SV-214838r609363_rule'
  tag stig_id: 'AOSX-13-000330'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-16036r466226_fix'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144']
  tag 'documentable'
  tag legacy: ['V-81537', 'SV-96251']
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']
end

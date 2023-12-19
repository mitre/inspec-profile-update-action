control 'SV-257151' do
  title 'The macOS system must compare internal information system clocks at least every 24 hours with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DOD network (NIPRNet/SIPRNet) and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. 

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

'
  desc 'check', 'Verify the macOS system is configured with the timed service enabled and an authorized time server with the following commands:

/usr/bin/sudo /usr/sbin/systemsetup -getusingnetworktime

Network Time: On

If "Network Time" is not set to "On", this is a finding.

/usr/bin/sudo /usr/sbin/systemsetup -getnetworktimeserver

If no time server is configured, or if an unapproved time server is in use, this is a finding.'
  desc 'fix', 'Configure the macOS system to enable the timed service and set an authorized time server with the following commands:

/usr/bin/sudo /usr/sbin/systemsetup -setusingnetworktime on

/usr/bin/sudo /usr/sbin/systemsetup -setnetworktimeserver "server"'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60836r922871_chk'
  tag severity: 'medium'
  tag gid: 'V-257151'
  tag rid: 'SV-257151r922872_rule'
  tag stig_id: 'APPL-13-000014'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-60777r905085_fix'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144']
  tag 'documentable'
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']
end

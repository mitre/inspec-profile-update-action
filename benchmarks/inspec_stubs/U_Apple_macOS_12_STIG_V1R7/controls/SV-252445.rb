control 'SV-252445' do
  title 'The macOS system must, for networked systems, compare internal information system clocks at least every 24 hours with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet) and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. 

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

'
  desc 'check', 'The TIMED (NTP replacement in Big Sur) service must be enabled on all networked systems. To check if the service is running, use the following command:

sudo systemsetup -getusingnetworktime

If the following in not returned, this is a finding:
Network Time: On

To verify that an authorized Time Server is configured, run the following command:
 sudo systemsetup -getnetworktimeserver

Only approved time servers should be configured for use.

If no server is configured, or if an unapproved time server is in use, this is a finding.'
  desc 'fix', 'To enable the TIMED service, run the following command:

/usr/bin/sudo systemsetup -setusingnetworktime on

To configure a time server, use the following command:

/usr/bin/sudo systemsetup -setnetworktimeserver "server"'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55901r816147_chk'
  tag severity: 'medium'
  tag gid: 'V-252445'
  tag rid: 'SV-252445r877038_rule'
  tag stig_id: 'APPL-12-000014'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-55851r816148_fix'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144']
  tag 'documentable'
  tag cci: ['CCI-002046', 'CCI-001891']
  tag nist: ['AU-8 (1) (b)', 'AU-8 (1) (a)']
end

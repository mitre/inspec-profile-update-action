control 'SV-254182' do
  title 'Nutanix AOS must compare internal information system clocks at least every 24 hours with a server synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

'
  desc 'check', 'Confirm Nutanix AOS is running the NTP service.

# sudo ps -ef | grep ntp
ntp       7447     1  0 Aug17 ?        00:00:05 /usr/sbin/ntpd -u ntp:ntp -g

If the NTP service is not running, this is a finding.

Next Check the ntp.conf file for the "maxpoll" option setting.

$ sudo grep maxpoll /etc/ntp.conf
server #.#.#.# maxpoll 10

If the option is set to "17" or is not set, this is a finding.'
  desc 'fix', 'Log in to the Nutanix CVM.

Run the following command to add a list of DoD Approved NTP servers:  $ ncli cluster add-to-ntp-servers servers=IP_1,IP_2,IP_3'
  impact 0.3
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57667r846632_chk'
  tag severity: 'low'
  tag gid: 'V-254182'
  tag rid: 'SV-254182r846801_rule'
  tag stig_id: 'NUTX-OS-000890'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-57618r846633_fix'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144']
  tag 'documentable'
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']
end

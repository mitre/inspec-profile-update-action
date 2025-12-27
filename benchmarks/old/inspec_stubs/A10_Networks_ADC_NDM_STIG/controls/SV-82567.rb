control 'SV-82567' do
  title 'The A10 Networks ADC must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Review the device configuration.

The following command shows clock information:
show clock detail

If the output does not show NTP as the time source, this is a finding.

If a dot appears in front of the time, the device has been configured to use NTP, but NTP is not synchronized. This is also a finding.'
  desc 'fix', 'Up to four NTP servers can be configured. The following commands set the NTP server and enable the Network Time Protocol:
ntp server [hostname | ipaddr]
ntp enable'
  impact 0.3
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68637r1_chk'
  tag severity: 'low'
  tag gid: 'V-68077'
  tag rid: 'SV-82567r1_rule'
  tag stig_id: 'AADC-NM-000099'
  tag gtitle: 'SRG-APP-000371-NDM-000296'
  tag fix_id: 'F-74193r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end

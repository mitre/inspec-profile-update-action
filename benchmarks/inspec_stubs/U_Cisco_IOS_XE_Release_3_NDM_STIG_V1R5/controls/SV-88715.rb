control 'SV-88715' do
  title 'The Cisco IOS XE router must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity.  Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Verify that at least two NTP servers are configured and that system clocks update the time every 24 hours.

The configuration should look similar to the example below:

ntp authentication-key 1 md5 072C285F4D06 7
ntp authenticate
ntp trusted-key 1
ntp server 1.1.1.1 key 1

If there are not at least two NTP servers configured, and clocks are updated at least every 24 hours, this is a finding.'
  desc 'fix', 'Configure the router to use NTP.

The configuration should look similar to the example below:

ntp authentication-key 1 md5 072C285F4D06 7
ntp authenticate
ntp trusted-key 1
ntp server 1.1.1.1 key 1'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74131r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74041'
  tag rid: 'SV-88715r2_rule'
  tag stig_id: 'CISR-ND-000100'
  tag gtitle: 'SRG-APP-000371-NDM-000296'
  tag fix_id: 'F-80583r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end

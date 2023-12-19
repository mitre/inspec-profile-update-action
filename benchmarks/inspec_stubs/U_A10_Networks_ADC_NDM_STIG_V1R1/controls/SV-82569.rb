control 'SV-82569' do
  title 'The A10 Networks ADC must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in CCI-001891 because a comparison must be done in order to determine the time difference.

The organization-defined time period will depend on multiple factors, most notably the granularity of time stamps in audit logs. For example, if time stamps only show to the nearest second, there is no need to have accuracy of a tenth of a second in clocks.'
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
  tag check_id: 'C-68639r1_chk'
  tag severity: 'low'
  tag gid: 'V-68079'
  tag rid: 'SV-82569r1_rule'
  tag stig_id: 'AADC-NM-000100'
  tag gtitle: 'SRG-APP-000372-NDM-000297'
  tag fix_id: 'F-74195r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end

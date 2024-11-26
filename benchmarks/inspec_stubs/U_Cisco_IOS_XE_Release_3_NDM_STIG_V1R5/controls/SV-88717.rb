control 'SV-88717' do
  title 'The Cisco IOS XE router must synchronize internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in CCI-001891 because a comparison must be done in order to determine the time difference.

The organization-defined time period will depend on multiple factors, most notably the granularity of time stamps in audit logs. For example, if time stamps only show to the nearest second, there is no need to have accuracy of a tenth of a second in clocks.'
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
  tag check_id: 'C-74133r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74043'
  tag rid: 'SV-88717r2_rule'
  tag stig_id: 'CISR-ND-000101'
  tag gtitle: 'SRG-APP-000372-NDM-000297'
  tag fix_id: 'F-80585r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end

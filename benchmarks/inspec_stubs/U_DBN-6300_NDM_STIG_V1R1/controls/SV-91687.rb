control 'SV-91687' do
  title 'The DBN-6300 must synchronize its internal system clock to the NTP server when the time difference is greater than one second.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in CCI-001891 because a comparison must be done in order to determine the time difference.

The organization-defined time period will depend on multiple factors, most notably the granularity of time stamps in audit logs. For example, if time stamps only show to the nearest second, there is no need to have accuracy of a tenth of a second in clocks.'
  desc 'check', 'Verify the configuration of the NTP server.

Navigate to Settings >> Initial Configuration >> Time.

View the "Time" settings window.

If an NTP server address is not configured, this is a finding.'
  desc 'fix', 'Configure the NTP server on the device. The time difference is part of the NTP protocol and is not configurable.

Navigate to Settings >> Initial Configuration >> Time.

In the "Time" settings window, select the "NTP" button and enter the NTP server address.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76617r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76991'
  tag rid: 'SV-91687r1_rule'
  tag stig_id: 'DBNW-DM-000101'
  tag gtitle: 'SRG-APP-000372-NDM-000297'
  tag fix_id: 'F-83687r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end

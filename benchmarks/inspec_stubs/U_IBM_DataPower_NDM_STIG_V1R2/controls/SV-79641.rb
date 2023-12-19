control 'SV-79641' do
  title 'The DataPower Gateway must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in CCI-001891 because a comparison must be done in order to determine the time difference.

The organization-defined time period will depend on multiple factors, most notably the granularity of time stamps in audit logs. For example, if time stamps only show to the nearest second, there is no need to have accuracy of a tenth of a second in clocks.'
  desc 'check', 'Using the DataPower web interface, go to Network >> Interface >> NTP Service. Confirm that the Administrative state is enabled, NTP Servers are configured, and that the Refresh Interval is set to 2040 seconds or less. If it is not, this is a finding.'
  desc 'fix', 'Configure the DataPower Gateway to synchronize internal information system clocks to the authoritative time source (NTP servers).

In the DataPower WebGUI, go to Network >> Interface >> NTP Service. Specify the IP addresses of several approved NTP servers. The refresh interval may be defined at any value between 60 and 86400 seconds.'
  impact 0.3
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65779r1_chk'
  tag severity: 'low'
  tag gid: 'V-65151'
  tag rid: 'SV-79641r1_rule'
  tag stig_id: 'WSDP-NM-000099'
  tag gtitle: 'SRG-APP-000372-NDM-000297'
  tag fix_id: 'F-71091r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end

control 'SV-75321' do
  title 'The Arista Multilayer Switch must synchronize internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in CCI-001891 because a comparison must be done in order to determine the time difference.

The organization-defined time period will depend on multiple factors, most notably the granularity of time stamps in audit logs. For example, if time stamps only show to the nearest second, there is no need to have accuracy of a tenth of a second in clocks.'
  desc 'check', 'Check the network device configuration to determine if the device synchronizes internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period. 

If this synchronization is not occurring when the time difference is greater than the organization-defined time period, this is a finding.

Verify with the "show NTP status" command, which shows the state of device synchronization.'
  desc 'fix', 'Configure the network device to synchronize internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.

Configuration Example:
switch(config)#ntp server HOST
switch(config)#ntp server HOST prefer'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60863'
  tag rid: 'SV-75321r1_rule'
  tag stig_id: 'AMLS-NM-000270'
  tag gtitle: 'SRG-APP-000372-NDM-000297'
  tag fix_id: 'F-66575r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end

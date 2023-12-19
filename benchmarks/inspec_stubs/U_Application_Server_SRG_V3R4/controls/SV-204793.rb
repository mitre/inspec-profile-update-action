control 'SV-204793' do
  title 'The application server must synchronize internal application server clocks to an authoritative time source when the time difference is greater than the organization-defined time period.'
  desc 'Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

Synchronization of internal application server clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. To meet this requirement, the organization will define an authoritative time source and have each system synchronize when the time difference is greater than a defined time period.  The industry standard for the threshold is 1ms.'
  desc 'check', 'Review application server documentation and configuration to determine if the application server is configured to reset internal information clocks when the difference is greater than a defined threshold with an authoritative time source.

If the application server cannot synchronize internal application server clocks to the authoritative time source when the time difference is greater than the organization-defined time period, this is a finding.'
  desc 'fix', 'Configure the application server to reset internal information system clocks when the time difference is greater than a defined time period with the authoritative time source.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4913r283026_chk'
  tag severity: 'medium'
  tag gid: 'V-204793'
  tag rid: 'SV-204793r879745_rule'
  tag stig_id: 'SRG-APP-000372-AS-000212'
  tag gtitle: 'SRG-APP-000372'
  tag fix_id: 'F-4913r283027_fix'
  tag 'documentable'
  tag legacy: ['SV-71709', 'V-57437']
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end

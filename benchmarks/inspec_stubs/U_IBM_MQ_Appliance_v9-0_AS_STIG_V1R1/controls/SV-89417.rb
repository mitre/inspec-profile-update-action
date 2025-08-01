control 'SV-89417' do
  title 'The MQ Appliance messaging server must synchronize internal MQ Appliance messaging server clocks to an authoritative time source when the time difference is greater than the organization-defined time period.'
  desc 'Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

Synchronization of internal messaging server clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. To meet this requirement, the organization will define an authoritative time source and have each system synchronize when the time difference is greater than a defined time period.  The industry standard for the threshold is 1ms.'
  desc 'check', 'Log on as a privileged user to the WebGUI.
Select Network icon. 
Interface NTP Service.
Verify that refresh interval is set to "600" seconds.

If refresh interval is not set to "600" seconds, this is a finding.'
  desc 'fix', 'Log on as a privileged user to the WebGUI.
Select the  Network icon.
Interface NTP Service.

Set refresh interval to "600" seconds.

Click "Save configuration".'
  impact 0.3
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74599r1_chk'
  tag severity: 'low'
  tag gid: 'V-74743'
  tag rid: 'SV-89417r1_rule'
  tag stig_id: 'MQMH-AS-000160'
  tag gtitle: 'SRG-APP-000372-AS-000212'
  tag fix_id: 'F-81359r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end

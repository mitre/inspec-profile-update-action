control 'SV-89419' do
  title 'The MQ Appliance messaging server must compare internal MQ Appliance messaging server clocks at least every 24 hours with an authoritative time source.'
  desc 'Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

Synchronization of system clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. To meet this requirement, the organization will define an authoritative time source and have each system compare its internal clock at least every 24 hours.'
  desc 'check', 'Log on as a privileged user to the WebGUI.
Select Network icon.
Interface NTP Service.

Verify: 
- NTP server destinations are configured.
- "Enable Administrative state" box is checked.

If "Enable Administrative state" is not checked or if no NTP servers are defined, this is a finding.'
  desc 'fix', 'Log on as a privileged user to the WebGUI.
Select the  Network icon.
Interface NTP Service.

Ensure the box next to "Enable Administrative state" has a check mark.
Press the "Add" button to add multiple NTP servers.
Click the "Apply" button.

Add one or more additional NTP servers at least one of which is from a different geographic region.

Click "Save configuration".'
  impact 0.3
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74601r1_chk'
  tag severity: 'low'
  tag gid: 'V-74745'
  tag rid: 'SV-89419r1_rule'
  tag stig_id: 'MQMH-AS-000170'
  tag gtitle: 'SRG-APP-000371-AS-000077'
  tag fix_id: 'F-81361r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end

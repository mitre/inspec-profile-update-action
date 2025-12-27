control 'SV-81543' do
  title 'The Tanium IOC Detect module must be configured to forward events.'
  desc 'Indicators of Compromise (IOC) is an artifact which is observed on the network or system that indicates computer intrusion. The Tanium IOC Detect module detects, manages, and analyzes systems against IOCs real-time. The module also responds to those detections.

By forwarding events the IOC Detect module, using Tanium Connect with a syslog or SIEM connection, captures the necessary forensic evidence supporting a compromise is retained.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "IOC Detect".

Along the right column of the interface, click on the “gear” icon.

The “Workbench Settings” menu will be displayed.

Click on the “wrench” icon under "Event Forwarding".

If "Forwarding Target" is "Disabled", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "IOC Detect".

Along the right column of the interface, click on the “gear” icon.

The “Workbench Settings” menu will be displayed.

Click on the “wrench” icon under "Event Forwarding".

Configured the "Event Forwarding" to be configured for "Syslog".

If a syslog is already configured under Tanium Connect, the value for "Event Forwarding" may be configured to "Tanium Connect".

Click on "Save Changes".'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67689r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67053'
  tag rid: 'SV-81543r1_rule'
  tag stig_id: 'TANS-SV-000010'
  tag gtitle: 'SRG-APP-000115'
  tag fix_id: 'F-73153r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end

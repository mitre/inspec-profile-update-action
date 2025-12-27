control 'SV-93379' do
  title 'The Tanium Connect module must be configured to forward Tanium IOC Detect events to identified destinations.'
  desc 'Indicators of Compromise (IOC) is an artifact that is observed on the network or system that indicates computer intrusion. The Tanium IOC Detect module detects, manages, and analyzes systems against IOCs real-time. The module also responds to those detections.

By forwarding events the IOC Detect module, using Tanium Connect with a syslog or SIEM connection, captures the necessary forensic evidence supporting a compromise is retained.'
  desc 'check', 'Consult with the Tanium System Administrator to determine if the "Tanium Detect" module is being used. If it is not, this is "Not Applicable".

Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Click "Events" under "Sources".

Verify the "Tanium IOC Detect" event is being sent to an identified destination.

If there is no "Tanium IOC Detect" event source, this is a finding.'
  desc 'fix', 'Consult with the Tanium System Administrator to determine if the "Tanium Detect" module is being used. If it is not, this is "Not Applicable".

Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Click "Create Connection".

Give the Connection a name and description.

Select "Events" as the source.

Event Group should be "Tanium IOC Detect".

Select the appropriate events to send.

Consult with the Tanium System Administrator for the Destination.

Click "Create Connection".'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78243r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78673'
  tag rid: 'SV-93379r1_rule'
  tag stig_id: 'TANS-SV-000010'
  tag gtitle: 'SRG-APP-000115'
  tag fix_id: 'F-85409r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end

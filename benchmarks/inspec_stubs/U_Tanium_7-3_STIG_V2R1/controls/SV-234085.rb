control 'SV-234085' do
  title 'The Tanium Connect module must be configured to forward Tanium Detect events to identified destinations.'
  desc 'Indicators of Compromise (IOC) are artifacts, which are observed on the network or system that indicates computer intrusion. The Tanium Detect module detects, manages, and analyzes systems intrusion in real time. The module also responds to those detections.

By forwarding Detect events using Tanium Connect, the necessary forensic evidence supporting a compromise is retained.'
  desc 'check', 'Consult with the Tanium System Administrator to determine if the "Tanium Detect" module is being used.

If it is not, this is Not Applicable.

Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Click "Events" under "Sources".

Verify the "Tanium IOC Detect" event is being sent to an identified destination.

If there is no "Tanium IOC Detect" event source, this is a finding.'
  desc 'fix', 'Consult with the Tanium System Administrator to determine if the "Tanium Detect" module is being used.

If not this is Not Applicable.

Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Click "New Connection".

Click "Create" or if importing "Import".

Give the "Connection" a name and description.

Select "Events" as the source.

"Event Group" should be "Tanium Detect".

Select the appropriate events to send.

Consult with the Tanium System Administrator for the Destination.

Click "Create Connection".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37270r610755_chk'
  tag severity: 'medium'
  tag gid: 'V-234085'
  tag rid: 'SV-234085r612749_rule'
  tag stig_id: 'TANS-SV-000010'
  tag gtitle: 'SRG-APP-000115'
  tag fix_id: 'F-37235r610756_fix'
  tag 'documentable'
  tag legacy: ['SV-102243', 'V-92141']
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end

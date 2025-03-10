control 'SV-234086' do
  title 'The Tanium cryptographic signing capabilities must be enabled on the Tanium Server.'
  desc "All of Tanium's signing capabilities should be enabled upon install. Tanium supports the cryptographic signing and verification before execution of all Sensors, Questions, Actions, Sensor Libraries, File Shards, etc. Enabling signing does away with the ability of an attacker to conduct Man in the Middle (MitM) attacks for the purposes of remote code execution and precludes the modification of the aforementioned data elements in transit. Additionally, Tanium supports object level signing for content ingested into the Tanium platform. This allows for the detection and rejection of changes to objects (sensors, actions, etc.) by even a privileged user within Tanium.

Tanium has built-in signing capabilities enabled by default when installed. Cryptographic signing and verification of all Sensors, Questions, Actions, Sensor Libraries, File Shards, etc. before execution will be enforced by Tanium.

Signing will prevent MitM remote code execution attacks and will protect data element in transit. Tanium also supports object level signing for content within the Tanium platform.

"
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

In the "Show Settings Containing:" search box type "sign_all_questions_flag".

Click "Enter".

If no results are returned, this is a finding.

If results are returned for "sign_all_questions_flag" but the value is not "1", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

Click on "New Setting".

In "New System Setting" dialog box, enter "sign_all_questions_flag" for "Setting Name:".

Enter "1" for "Setting Value:".

Select "Server" from "Affects" drop-down list.

Select "Numeric" from "Value Type" drop-down list.

Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37271r610758_chk'
  tag severity: 'medium'
  tag gid: 'V-234086'
  tag rid: 'SV-234086r612749_rule'
  tag stig_id: 'TANS-SV-000014'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-37236r610759_fix'
  tag satisfies: ['SRG-APP-000131', 'SRG-APP-000233', 'SRG-APP-000317']
  tag 'documentable'
  tag legacy: ['SV-102245', 'V-92143']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

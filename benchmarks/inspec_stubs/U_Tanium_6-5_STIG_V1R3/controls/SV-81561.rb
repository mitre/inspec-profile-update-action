control 'SV-81561' do
  title 'The Tanium cryptographic signing capabilities must be enabled on the Tanium Server.'
  desc "All of Tanium's signing capabilities should be enabled upon install. Tanium supports the cryptographic signing and verification before execution of all Sensors, Questions, Actions, Sensor Libraries, File Shards, etc. Enabling signing does away with the ability of an attacker to conduct Man in the Middle (MitM) attacks for the purposes of remote code execution and precludes the modification of the aforementioned data elements in transit. Additionally, Tanium supports object level signing for content ingested into the Tanium platform. This allows for the detection and rejection of changes to objects (sensors, actions, etc.) by even a privileged user within Tanium.

Tanium has built-in signing capabilities enabled by default when installed. Cryptographic signing and verification of all Sensors, Questions, Actions, Sensor Libraries, File Shards, etc. before execution will be enforced by Tanium. 

Signing will prevent MitM remote code execution attacks and will protect data element in transit. Tanium also supports object level signing for content within the Tanium platform."
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Global Settings" tab.

In the search box beside "Show Settings Containing:" type "sign_all_questions_flag".  Enter.

If no results are returned, this is a finding since this setting needs to be explicitly set.

If results are returned for “sign_all_questions_flag” but the value is not "1", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Global Settings" tab.

Click on "+ Add New Setting".

In "Create New Setting" dialog box, enter "sign_all_questions_flag" for "Setting Name:".

Enter "1" for "Setting Value:".

Select "Numeric" from "Value Type" drop-down list.

Select "Server" from "Affects" drop-down list.

Click “Save”.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67071'
  tag rid: 'SV-81561r1_rule'
  tag stig_id: 'TANS-SV-000014'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-73171r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

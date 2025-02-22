control 'SV-254903' do
  title 'The Tanium cryptographic signing capabilities must be enabled on the Tanium Clients to safeguard the authenticity of communications sessions when answering requests from the Tanium Server.'
  desc "All of Tanium's signing capabilities should be enabled upon install. Tanium supports the cryptographic signing and verification before execution of all Sensors, Questions, Actions, Sensor Libraries, File Shards, etc. Enabling signing does away with the ability of an attacker to conduct Man in the Middle (MitM) attacks for the purposes of remote code execution and precludes the modification of the aforementioned data elements in transit. Additionally, Tanium supports object level signing for content ingested into the Tanium platform. This allows for the detection and rejection of changes to objects (sensors, actions, etc.) by even a privileged user within Tanium.

Tanium has built-in signing capabilities enabled by default when installed. Cryptographic signing and verification of all Sensors, Questions, Actions, Sensor Libraries, File Shards, etc. before execution will be enforced by Tanium.

Signing will prevent MitM remote code execution attacks and will protect data element in transit. Tanium also supports object level signing for content within the Tanium platform.

"
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration," select "Platform Settings".

4. In the "Filter Items" search box type "AllQuestionsRequireSignatureFlag".

5. Click "Enter".

If no results are returned, this is a finding.

If results are returned for "AllQuestionsRequireSignatureFlag" but the value is not "1", this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration," select "Platform Settings".

4. Click "Create Setting".

5. Select "Client" box for "Setting Type."

6. In "Create Platform Setting" dialog box, enter "AllQuestionsRequireSignatureFlag" for "Name".

7. Select "Numeric" radio button for "Value Type".

8. Enter "1" for "Value".

9. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58516r867607_chk'
  tag severity: 'medium'
  tag gid: 'V-254903'
  tag rid: 'SV-254903r867609_rule'
  tag stig_id: 'TANS-AP-000330'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-58460r867608_fix'
  tag satisfies: ['SRG-APP-000131', 'SRG-APP-000219']
  tag 'documentable'
  tag cci: ['CCI-001184', 'CCI-001749']
  tag nist: ['SC-23', 'CM-5 (3)']
end

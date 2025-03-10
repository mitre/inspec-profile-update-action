control 'SV-234686' do
  title 'Oracle JRE 8 must default to the most secure built-in setting.'
  desc 'Applications that are signed with a valid certificate and include the permissions attribute in the manifest for the main JAR file are allowed to run with security prompts. All other applications are blocked. Unsigned applications could perform numerous types of attacks on a system.'
  desc 'check', 'Navigate to the system-level "deployment.properties" file for JRE.

<Windows Directory>\\Sun\\Java\\Deployment\\deployment.properties
- or -
<JRE Installation Directory>\\Lib\\deployment.properties

If the key "deployment.security.level=VERY_HIGH" is not present in the "deployment.properties file", or is set to "HIGH", this is a finding.

If the key "deployment.security.level.locked" is not present in the "deployment.properties" file, this is a finding.'
  desc 'fix', 'Navigate to the system-level "deployment.properties" file for JRE.

Add the key "deployment.security.level=VERY_HIGH" to the "deployment.properties" file.

Add the key "deployment.security.level.locked" to the "deployment.properties" file.'
  impact 0.3
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37871r616114_chk'
  tag severity: 'low'
  tag gid: 'V-234686'
  tag rid: 'SV-234686r617446_rule'
  tag stig_id: 'JRE8-WN-000060'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37836r616115_fix'
  tag 'documentable'
  tag legacy: ['V-66945', 'SV-81435']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

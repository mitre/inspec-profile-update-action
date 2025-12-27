control 'SV-81403' do
  title 'Oracle JRE 8 must default to the most secure built-in setting.'
  desc 'Applications that are signed with a valid certificate and include the permissions attribute in the manifest for the main JAR file are allowed to run with security prompts. All other applications are blocked. Unsigned applications could perform numerous types of attacks on a system.'
  desc 'check', 'Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

If the key “deployment.security.level=VERY_HIGH” is not present in the deployment.properties file, or is set to “HIGH”, this is a finding. 

If the key “deployment.security.level.locked” is not present in the deployment.properties file, this is a finding.'
  desc 'fix', 'Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

Add the key “deployment.security.level=VERY_HIGH” to the deployment.properties file.
Add the key “deployment.security.level.locked” to the deployment.properties file.'
  impact 0.3
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67549r1_chk'
  tag severity: 'low'
  tag gid: 'V-66913'
  tag rid: 'SV-81403r1_rule'
  tag stig_id: 'JRE8-UX-000060'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-73013r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-234687' do
  title 'Oracle JRE 8 must be set to allow Java Web Start (JWS) applications.'
  desc 'Java Web Start (JWS) applications are the most commonly used.  Denying these applications could be detrimental to the user experience. Whitelisting, blacklisting, and signing of applications help mitigate the risk of running JWS applications.'
  desc 'check', 'Navigate to the system-level “deployment.properties” file for JRE.

The location of the deployment.properties file is defined in <JRE Installation Directory>\\Lib\\deployment.config

If the key “deployment.webjava.enabled=true” is not present in the deployment.properties file, or is set to “false”, this is a finding.

If the key “deployment.webjava.enabled.locked” is not present in the deployment.properties file, this is a finding.

Note: If JWS is not enabled, this requirement is NA.'
  desc 'fix', 'Navigate to the system-level “deployment.properties” file for JRE.

The location of the deployment.properties file is defined in <JRE Installation Directory>\\Lib\\deployment.config

Add the key “deployment.webjava.enabled=true” to the deployment.properties file.

Add the key “deployment.webjava.enabled.locked” to the deployment.properties file.

Note: If JWS is not enabled, this requirement is NA.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37872r616117_chk'
  tag severity: 'medium'
  tag gid: 'V-234687'
  tag rid: 'SV-234687r617446_rule'
  tag stig_id: 'JRE8-WN-000070'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37837r616118_fix'
  tag 'documentable'
  tag legacy: ['V-66947', 'SV-81437']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

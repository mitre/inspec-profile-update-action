control 'SV-81405' do
  title 'Oracle JRE 8 must be set to allow Java Web Start (JWS) applications.'
  desc 'Java Web Start (JWS) applications are the most commonly used.  Denying these applications could be detrimental to the user experience. Whitelisting, blacklisting, and signing of applications help mitigate the risk of running JWS applications.'
  desc 'check', 'Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

If the key “deployment.webjava.enabled=true” is not present in the deployment.properties file, or is set to “false”, this is a finding.

If the key “deployment.webjava.enabled.locked” is not present in the deployment.properties file, this is a finding.'
  desc 'fix', 'Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

Add the key “deployment.webjava.enabled=true” to the deployment.properties file.

Add the key “deployment.webjava.enabled.locked” to the deployment.properties file.'
  impact 0.5
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67551r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66915'
  tag rid: 'SV-81405r1_rule'
  tag stig_id: 'JRE8-UX-000070'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-73015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

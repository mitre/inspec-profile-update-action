control 'SV-81423' do
  title 'Oracle JRE 8 must prompt the user for action prior to executing mobile code.'
  desc 'Mobile code can cause damage to the system. It can execute without explicit action from, or notification to, a user. 

Actions enforced before executing mobile code include, for example, prompting users prior to opening email attachments and disabling automatic execution.

This requirement applies to mobile code-enabled software, which is capable of executing one or more types of mobile code.'
  desc 'check', 'Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

If the key “deployment.insecure.jres=PROMPT” is not present in the deployment.properties file, this is a finding.

If the key “deployment.insecure.jres.locked” is not present in the deployment.properties file, this is a finding.

If the key “deployment.insecure.jres” is set to “NEVER”, this is a finding.'
  desc 'fix', 'Navigate to the system-level “deployment.properties” file for JRE.

/etc/.java/deployment/deployment.properties

Add the key “deployment.insecure.jres=PROMPT” to the deployment.properties file.

Add the key “deployment.insecure.jres.locked” to the deployment.properties file.'
  impact 0.5
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67569r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66933'
  tag rid: 'SV-81423r1_rule'
  tag stig_id: 'JRE8-UX-000170'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-73033r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end

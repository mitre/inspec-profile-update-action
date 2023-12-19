control 'SV-234696' do
  title 'Oracle JRE 8 must prompt the user for action prior to executing mobile code.'
  desc 'Mobile code can cause damage to the system. It can execute without explicit action from, or notification to, a user. 

Actions enforced before executing mobile code include, for example, prompting users prior to opening email attachments and disabling automatic execution.

This requirement applies to mobile code-enabled software, which is capable of executing one or more types of mobile code.'
  desc 'check', 'Navigate to the system-level "deployment.properties" file for JRE.

<Windows Directory>\\Sun\\Java\\Deployment\\deployment.properties
- or -
<JRE Installation Directory>\\Lib\\deployment.properties

If the key "deployment.insecure.jres=PROMPT" is not present in the "deployment.properties" file, this is a finding.

If the key "deployment.insecure.jres.locked" is not present in the "deployment.properties" file, this is a finding.

If the key "deployment.insecure.jres" is set to "NEVER", this is a finding.'
  desc 'fix', 'Navigate to the system-level "deployment.properties" file for JRE.

Add the key "deployment.insecure.jres=PROMPT" to the "deployment.properties" file.

Add the key "deployment.insecure.jres.locked" to the "deployment.properties" file.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37881r616144_chk'
  tag severity: 'medium'
  tag gid: 'V-234696'
  tag rid: 'SV-234696r617446_rule'
  tag stig_id: 'JRE8-WN-000170'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-37846r616145_fix'
  tag 'documentable'
  tag legacy: ['V-66963', 'SV-81453']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end

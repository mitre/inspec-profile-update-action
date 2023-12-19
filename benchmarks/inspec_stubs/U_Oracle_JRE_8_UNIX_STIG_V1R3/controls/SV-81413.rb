control 'SV-81413' do
  title 'Oracle JRE 8 must prevent the download of prohibited mobile code.'
  desc 'Decisions regarding the employment of mobile code within organizational information systems are based on the potential for the code to cause damage to the system if used maliciously. 

Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

Usage restrictions and implementation guidance apply to both the selection and use of mobile code installed, downloaded, or executed on all endpoints (e.g., servers, workstations, and smart phones). This requirement applies to applications that execute, evaluate, or otherwise process mobile code (e.g., web applications, browsers, and anti-virus applications).'
  desc 'check', 'Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

If the key “deployment.security.blacklist.check=true” is not present in the deployment.properties file, or is set to “false”, this is a finding.

If the key “deployment.security.blacklist.check.locked” is not present in the deployment.properties file, this is a finding.'
  desc 'fix', 'Navigate to the system-level “deployment.properties” file for JRE.  

/etc/.java/deployment/deployment.properties

Add the key “deployment.security.blacklist.check=true” to the deployment.properties file.

Add the key “deployment.security.blacklist.check.locked” to the deployment.properties file.'
  impact 0.5
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67559r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66923'
  tag rid: 'SV-81413r1_rule'
  tag stig_id: 'JRE8-UX-000110'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-73023r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end

control 'SV-81415' do
  title 'Oracle JRE 8 must enable the option to use an accepted sites list.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of whitelisted software can occur either prior to execution or at system startup.

This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers).'
  desc 'check', 'Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

If the key “deployment.user.security.exception.sites” is not present in the deployment.properties file, this is a finding.

If the key “deployment.user.security.exception.sites” is not set to the location of the exception.sites file, this is a finding.

An example of a correct setting is:
deployment.user.security.exception.sites=/etc/.java/deployment/exception.sites'
  desc 'fix', 'Navigate to the system-level “deployment.properties” file for JRE.  

 /etc/.java/deployment/deployment.properties

Add the key “deployment.user.security.exception.sites=/etc/.java/deployment/exception.sites” to the deployment.properties file.'
  impact 0.5
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67561r2_chk'
  tag severity: 'medium'
  tag gid: 'V-66925'
  tag rid: 'SV-81415r2_rule'
  tag stig_id: 'JRE8-UX-000120'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-73025r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

control 'SV-234692' do
  title 'Oracle JRE 8 must enable the option to use an accepted sites list.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of whitelisted software can occur either prior to execution or at system startup.

This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers).'
  desc 'check', 'Navigate to the system-level "deployment.properties" file for JRE.

<Windows Directory>\\Sun\\Java\\Deployment\\deployment.properties
- or -
<JRE Installation Directory>\\Lib\\deployment.properties

If the key "deployment.user.security.exception.sites" is not present in the "deployment.properties" file, this is a finding. 

If the key "deployment.user.security.exception.sites" is not set to the location of the "exception.sites" file, this is a finding.

An example of a correct setting is:
deployment.user.security.exception.sites=C\\:\\\\Windows\\\\Sun\\\\Java\\\\Deployment\\\\exception.sites'
  desc 'fix', 'Navigate to the system-level "deployment.properties" file for JRE. 

Add the key "deployment.user.security.exception.sites=C\\:\\\\Windows\\\\Sun\\\\Java\\\\Deployment\\\\exception.sites" to the "deployment.properties" file.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37877r616132_chk'
  tag severity: 'medium'
  tag gid: 'V-234692'
  tag rid: 'SV-234692r617446_rule'
  tag stig_id: 'JRE8-WN-000120'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-37842r616133_fix'
  tag 'documentable'
  tag legacy: ['V-66957', 'SV-81447']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

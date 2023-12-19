control 'SV-234693' do
  title 'Oracle JRE 8 must have an exception.sites file present.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of whitelisted software can occur either prior to execution or at system startup.

This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers).'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the “exception.sites” file for Java:

The location of the "exception.sites" file is defined in the deployment.properties file.

The "exception.sites" file is a text file containing single-line URLs for accepted risk sites. If there are no AO approved sites to be added to the configuration, it is acceptable for this file to be blank.

If the “exception.sites” file does not exist, this is a finding.

If the “exception.sites” file contains URLs that are not AO approved, this is a finding.

Note: DeploymentRuleSet.jar is an acceptable substitute for using exception.sites.  Interview the SA to view contents of the "DeploymentRuleSet.jar" file to ensure any AO approved sites are whitelisted.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Create the JRE exception.sites file:
No default file exists. A text file named exception.sites, and the directory structure in which it is located must be manually created. The location must be aligned as defined in the deployment.properties file.
C:\\Windows\\Java\\Deployment\\deployment.properties is an example.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37878r616135_chk'
  tag severity: 'medium'
  tag gid: 'V-234693'
  tag rid: 'SV-234693r617446_rule'
  tag stig_id: 'JRE8-WN-000130'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-37843r616136_fix'
  tag 'documentable'
  tag legacy: ['V-66959', 'SV-81449']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

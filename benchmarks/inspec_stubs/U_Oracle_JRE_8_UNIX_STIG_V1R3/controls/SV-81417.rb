control 'SV-81417' do
  title 'Oracle JRE 8 must have an exception.sites file present.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of whitelisted software can occur either prior to execution or at system startup.

This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers).'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the “exception.sites” file for Java:

 /etc/.java/deployment/exception.sites

If the exception.sites file does not exist, it must be created. The exception.sites file is a text file containing single-line URLs for accepted risk sites.  If there are no AO approved sites to be added to the configuration, it is acceptable for this file to be blank.

If the “exception.sites” file does not exist, this is a finding.

If the “exception.sites” file contains URLs that are not AO approved, this is a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Create the JRE exception.sites file:

No default file exists. A text file named exception.sites, and the directory structure in which it is located must be manually created. The location must be aligned as defined in the deployment.properties file.

/etc/.java/deployment/deployment.properties is an example.'
  impact 0.5
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67563r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66927'
  tag rid: 'SV-81417r1_rule'
  tag stig_id: 'JRE8-UX-000130'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-73027r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

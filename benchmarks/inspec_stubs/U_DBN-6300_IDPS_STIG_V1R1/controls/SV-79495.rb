control 'SV-79495' do
  title 'The DBN-6300 must install system updates when new releases are available in accordance with organizational configuration management policy and procedures.'
  desc 'Failing to update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs. 
 
The IDPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, IDPS components must be updated, including application software files, anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures. 
 
Updates must be installed in accordance with the CCB procedures for the local organization. However, at a minimum:  
 
1. Updates designated as critical security updates by the vendor must be installed immediately.  
 
2. Updates for signature definitions, detection heuristics, and vendor-provided rules must be installed immediately. 
 
3. Updates for application software must be installed in accordance with the CCB procedures. 
 
4. Prior to automatically installing updates, either manual or automated integrity and authentication checking is required, at a minimum, for application software updates.'
  desc 'check', "To verify the current version is installed, navigate to the main screen of the DBN-6300. 
 
View the current running code that is visible in the upper-right corner of the screen. 
 
Log on to the organization's DB Networks SFTP site and view the version number of the current release. 
 
If the current code version does not match the version of the latest available release, this is a finding."
  desc 'fix', %q(Configure the DBN-6300 for system updates. 
 
Log on to the DB Networks SFTP site reserved specifically for the organization using the site's unique logon and password issued by DB Networks administrators. 
 
Using the SFTP protocol, navigate to the latest system image. Download this image to a local file repository. The file cannot be downloaded directly to the DBN-6300. 
 
If the machine with access to the DB Networks SFTP site does not have access, the upgrade image, once tested, may be moved to a system that does have direct connectivity to the DBN-6300 to be upgraded. 
 
Click on Tools >> File Management and click the "Upload File" button. A file navigation window will open. 
 
Navigate to the upgrade file and start the file upload. 
 
When file upload is complete, select "Tools" and click on the "Updates" button. 
 
Select the upgrade file and click on "Upgrade". 
 
After the upgrade is complete, click on Admin >> System Control >> Restart Production Mode to restart the system.)
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65663r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65005'
  tag rid: 'SV-79495r1_rule'
  tag stig_id: 'DBNW-IP-000024'
  tag gtitle: 'SRG-NET-000246-IDPS-00205'
  tag fix_id: 'F-70945r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end

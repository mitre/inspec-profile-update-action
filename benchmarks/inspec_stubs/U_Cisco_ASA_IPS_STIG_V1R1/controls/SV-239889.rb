control 'SV-239889' do
  title 'The Cisco ASA must be configured to automatically install updates to signature definitions and vendor-provided rules.'
  desc "Failing to automatically update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs. An automatic update process ensures this important task is performed without the need for system administrator intervention.

The IDPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, IDPS components must be automatically updated, including anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures.

If a DoD patch management server or update repository having the tested/verified updates is available for the IDPS component, the components must be configured to automatically check this server/site for updates and install new updates. 

If a DoD server/site is not available, the component must be configured to automatically check a trusted vendor site for updates. A trusted vendor is either commonly used by DoD, specifically approved by DoD, the vendor from which the equipment was purchased, or approved by the local program's CCB."
  desc 'check', 'Step 1: Select Configuration >> ASA FirePOWER Configuration >> Updates.

Step 2: Select the Rule Updates tab. The Rule Updates page appears.

Step 3: Verify that Enable Recurring Rule Update Imports has been selected.

Step 4: Verify that Daily, Weekly, or Monthly has been selected in the Import Frequency field.

Step 5: Verify that the following have been selected: 
- Reapply intrusion policies after the rule update import completes
- Reapply access control policies after the rule update import completes
  
Note: The Cisco Vulnerability Database (VDB) is a database of known vulnerabilities to which hosts may be susceptible. The Cisco Vulnerability Research Team (VRT) issues periodic updates to the VDB. Verify with the ASA administrator that product updates are installed on a regular basis.

If the ASA is not configured to install updates for signature definitions and vendor-provided rules, this is a finding.'
  desc 'fix', 'Apply Cisco Vulnerability Database (VDB) updates.

Step 1: Select Configuration >> ASA FirePOWER Configuration >> Updates. The Product Updates page appears.

Step 2: Click Download Updates to check for the latest updates on either of the following Support Sites:
- Sourcefire: https://support.sourcefire.com/
- Cisco: http://www.cisco.com/cisco/web/support/index.html

Step 3: Click the install icon next to the VDB update. The Install Update page appears.

Step 4: Click Install.
----------------------------------------------
Install Rule Updates Automatically.

Step 1: Select Configuration >> ASA FirePOWER Configuration >> Updates.

Step 2: Select the Rule Updates tab. The Rule Updates page appears.

Step 3: Select Enable Recurring Rule Update Imports.

Step 4: In the Import Frequency field, select Daily, Weekly, or Monthly from the drop-down list.

Step 5: Reapply policies after the update completes. Select Reapply intrusion policies after the rule update import completes. Select Reapply access control policies after the rule update import completes.
 
Step 6: Click Save.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43122r665978_chk'
  tag severity: 'medium'
  tag gid: 'V-239889'
  tag rid: 'SV-239889r665980_rule'
  tag stig_id: 'CASA-IP-000290'
  tag gtitle: 'SRG-NET-000251-IDPS-00178'
  tag fix_id: 'F-43081r665979_fix'
  tag 'documentable'
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end

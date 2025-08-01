control 'SV-239885' do
  title 'The Cisco ASA must be configured to install updates for signature definitions and vendor-provided rules.'
  desc 'Failing to update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs. 

The IDPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, IDPS components must be updated, including application software files, anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures.

Updates must be installed in accordance with the CCB procedures for the local organization. However, at a minimum: 

1. Updates designated as critical security updates by the vendor must be installed immediately.

2. Updates for signature definitions, detection heuristics, and vendor-provided rules must be installed immediately.

3. Updates for application software are installed in accordance with the CCB procedures.

4. Prior to automatically installing updates, either manual or automated integrity and authentication checking is required, at a minimum, for application software updates.'
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
  tag check_id: 'C-43118r665966_chk'
  tag severity: 'medium'
  tag gid: 'V-239885'
  tag rid: 'SV-239885r665968_rule'
  tag stig_id: 'CASA-IP-000240'
  tag gtitle: 'SRG-NET-000246-IDPS-00205'
  tag fix_id: 'F-43077r665967_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end

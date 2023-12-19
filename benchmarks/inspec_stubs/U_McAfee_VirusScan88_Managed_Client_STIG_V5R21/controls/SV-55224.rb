control 'SV-55224' do
  title 'McAfee VirusScan On-Access Default Processes Policies must be configured to scan when writing to disk.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are written to disk is a crucial first line of defense from malware attacks.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Scan Items tab, locate the "Scan files:" label. Ensure the "When writing to disk" option is selected.

Criteria:  If the "When writing to disk" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the value bScanIncoming is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Scan Items tab, locate the "Scan files:" label. Select the "When writing to disk" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48815r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14623'
  tag rid: 'SV-55224r1_rule'
  tag stig_id: 'DTAM101'
  tag gtitle: 'DTAM101-McAfee VirusScan scan when writing disk'
  tag fix_id: 'F-48079r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

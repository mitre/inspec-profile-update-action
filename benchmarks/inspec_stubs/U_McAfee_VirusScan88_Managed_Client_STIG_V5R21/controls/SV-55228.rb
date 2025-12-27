control 'SV-55228' do
  title 'McAfee VirusScan On-Access Default Processes Policies must be configured to scan all files.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Scan Items tab, locate the "File Types to Scan:" label. Ensure the "All Files" radio button is selected.

Criteria:  If the "All Files" radio button is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the value LocalExtensionMode is 1 and the value of NetworkExtensionMode is 1, this is not a finding. If either of these is not 1, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Scan Items tab, locate the "File Types to Scan:" label. Select the "All Files" radio button option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48818r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14625'
  tag rid: 'SV-55228r1_rule'
  tag stig_id: 'DTAM103'
  tag gtitle: 'DTAM103-McAfee VirusScan scan all files parameter'
  tag fix_id: 'F-48083r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

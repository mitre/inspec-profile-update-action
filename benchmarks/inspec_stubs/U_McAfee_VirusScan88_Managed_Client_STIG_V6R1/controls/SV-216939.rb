control 'SV-216939' do
  title 'McAfee VirusScan On-Access Default Processes Policies actions for When a threat is found must be configured delete files automatically if first action fails.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option so as to ensure the malware does is not introduced onto the system or network.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Actions tab, locate the "When a threat is found:" label. Ensure that from the "If the first action fails, then perform this action:" pull down menu, "Delete files automatically" is selected.

Criteria:  If "Delete files automatically" is selected for "If the first action fails, then perform this action:", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria: If the value for uSecAction is not 4, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Actions tab, locate the "When a threat is found:" label. From the "If the first action fails, then perform this action:" pull down menu, select "Delete files automatically". Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18169r309546_chk'
  tag severity: 'medium'
  tag gid: 'V-216939'
  tag rid: 'SV-216939r397870_rule'
  tag stig_id: 'DTAM111'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18167r309547_fix'
  tag 'documentable'
  tag legacy: ['SV-55234', 'V-14631']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

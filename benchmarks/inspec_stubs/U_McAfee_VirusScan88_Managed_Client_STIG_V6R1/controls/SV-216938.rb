control 'SV-216938' do
  title 'McAfee VirusScan On-Access Default Processes Policies Actions for When a threat is found must be configured to clean files automatically as first action.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option so as to ensure the malware does is not introduced onto the system or network.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Actions tab, locate the "When a threat is found:" label. Ensure that for the "Perform this action first:" pull down menu, "Clean files automatically" is selected.

Criteria:  If "Clean files automatically" is selected for "Perform this action first", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the value for uAction is not 5, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Actions tab, locate the "When a threat is found:" label. From the "Perform this action first:" pull down menu, select "Clean files automatically". Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18168r309543_chk'
  tag severity: 'medium'
  tag gid: 'V-216938'
  tag rid: 'SV-216938r397870_rule'
  tag stig_id: 'DTAM110'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18166r309544_fix'
  tag 'documentable'
  tag legacy: ['SV-55233', 'V-14630']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

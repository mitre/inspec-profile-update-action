control 'SV-216896' do
  title 'McAfee VirusScan On-Access General Policies must be configured to prevent users from removing messages from the list.'
  desc 'Good incident response analysis includes reviewing all logs and alerts on the system reporting the infection. If users were permitted to remove alerts from the display, incident response forensic analysis would be inhibited.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Messages tab, locate the "Actions available to user:" label. Ensure the "Remove messages from the list" option is NOT selected.

Criteria:  If the "Remove messages from the list" option is NOT selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value of Alert_UsersCanRemove is 0, this is not a finding. If the value is 1, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Messages tab, locate the "Actions available to user:" label. Uncheck the "Remove messages from the list" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18126r309417_chk'
  tag severity: 'medium'
  tag gid: 'V-216896'
  tag rid: 'SV-216896r397870_rule'
  tag stig_id: 'DTAM005'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18124r309418_fix'
  tag 'documentable'
  tag legacy: ['SV-55144', 'V-6470']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

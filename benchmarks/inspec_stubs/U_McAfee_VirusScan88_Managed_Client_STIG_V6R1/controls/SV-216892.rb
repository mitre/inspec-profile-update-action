control 'SV-216892' do
  title 'McAfee VirusScan On-Access General Policies must be configured to enable on-access scanning at system startup.'
  desc "For antivirus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, trojans, and other malware infecting the system during that startup phase."
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the General tab, locate the "Enable on-access scanning:" label. Ensure the "Enable on-access scanning at system startup" option is selected.

Criteria:  If the "Enable on-access scanning at startup" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value of bStartDisabled is 0, this is not a finding. If the value is 1, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the General tab, locate the "Enable on-access scanning:" label. Select the "Enable on-access scanning at system startup" option. Select Save.'
  impact 0.7
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18122r309405_chk'
  tag severity: 'high'
  tag gid: 'V-216892'
  tag rid: 'SV-216892r397870_rule'
  tag stig_id: 'DTAM001'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18120r309406_fix'
  tag 'documentable'
  tag legacy: ['SV-55134', 'V-6453']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

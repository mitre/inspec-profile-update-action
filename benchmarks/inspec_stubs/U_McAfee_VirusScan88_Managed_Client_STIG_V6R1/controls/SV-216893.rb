control 'SV-216893' do
  title 'McAfee VirusScan On-Access General Policies must be configured to scan boot sectors.'
  desc 'Boot sector viruses will install into the boot sector of a system, ensuring that they will execute when the user boots the system. This risk is mitigated by scanning boot sectors at each startup of the system.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the General tab, locate the "Scan:" label. Ensure the "Boot Sectors" option is selected.

Criteria:  If the "Boot Sectors" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value of bDontScanBootSectors is 0, this is not a finding. If the value is 1, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the General tab, locate the "Scan:" label. Select the "Boot Sectors" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18123r309408_chk'
  tag severity: 'medium'
  tag gid: 'V-216893'
  tag rid: 'SV-216893r397870_rule'
  tag stig_id: 'DTAM002'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18121r309409_fix'
  tag 'documentable'
  tag legacy: ['SV-55135', 'V-6467']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

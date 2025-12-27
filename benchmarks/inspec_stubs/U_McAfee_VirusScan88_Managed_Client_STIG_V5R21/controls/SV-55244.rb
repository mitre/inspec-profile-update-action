control 'SV-55244' do
  title 'McAfee VirusScan Access Protection Policies must be configured to prevent McAfee services from being stopped.'
  desc 'When the Prevent McAfee services from being stopped check box is selected under Access Protection, VSE will prevent anyone except the System account from terminating McAfee services. This protects VirusScan from being disabled by malicious programs that seek to circumvent virus protection programs by terminating their services.'
  desc 'check', 'Note: If the HIPS signature 3892 is enabled to provide the "Prevent termination of McAfee processes" protection, this check is not applicable. 

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection settings:" label. Ensure the "Prevent McAfee services from being stopped" option is selected.

Criteria:  If the "Prevent McAfee services from being stopped" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value of PVSPTEnabled is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection settings:" label. Select the "Prevent McAfee services from being stopped" option. Select Save.'
  impact 0.7
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48834r4_chk'
  tag severity: 'high'
  tag gid: 'V-42516'
  tag rid: 'SV-55244r2_rule'
  tag stig_id: 'DTAM138'
  tag gtitle: 'DTAM138 - Access Protection McAfee services protection'
  tag fix_id: 'F-48098r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

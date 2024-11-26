control 'SV-55277' do
  title 'McAfee VirusScan Access Protection Rules must be configured to prevent McAfee services from being stopped.'
  desc 'When the "Prevent McAfee services from being stopped" check box is selected under Access Protection, VSE will prevent anyone except the System account from terminating McAfee services. This protects VirusScan from being disabled by malicious programs that seek to circumvent virus protection programs by terminating their services.'
  desc 'check', 'Note: If the HIPS signature 3892 is enabled to provide the "Prevent termination of McAfee processes" protection, this check is not applicable. 

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, ensure the "Prevent McAfee services from being stopped" option is selected.

Criteria:  If the "Prevent McAfee services from being stopped" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value of PVSPTEnabled is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, select the "Prevent McAfee services from being stopped" option. 

Click OK to save.'
  impact 0.7
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49349r4_chk'
  tag severity: 'high'
  tag gid: 'V-42549'
  tag rid: 'SV-55277r2_rule'
  tag stig_id: 'DTAM138'
  tag gtitle: 'DTAM138 - Access Protection McAfee services protection'
  tag fix_id: 'F-48131r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

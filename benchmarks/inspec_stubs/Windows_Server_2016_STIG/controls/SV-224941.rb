control 'SV-224941' do
  title 'Explorer Data Execution Prevention must be enabled.'
  desc 'Data Execution Prevention provides additional protection by performing checks on memory to help prevent malicious code from running. This setting will prevent Data Execution Prevention from being turned off for File Explorer.'
  desc 'check', 'The default behavior is for Data Execution Prevention to be turned on for File Explorer.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoDataExecutionPrevention

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for data execution prevention to be turned on for File Explorer.

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Turn off Data Execution Prevention for Explorer" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26632r465725_chk'
  tag severity: 'medium'
  tag gid: 'V-224941'
  tag rid: 'SV-224941r852331_rule'
  tag stig_id: 'WN16-CC-000340'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-26620r465726_fix'
  tag 'documentable'
  tag legacy: ['SV-88225', 'V-73561']
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end

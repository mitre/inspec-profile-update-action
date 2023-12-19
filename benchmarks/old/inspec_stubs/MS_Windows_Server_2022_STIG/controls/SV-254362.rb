control 'SV-254362' do
  title 'Windows Server 2022 Explorer Data Execution Prevention must be enabled.'
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

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> Turn off Data Execution Prevention for Explorer to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57847r848900_chk'
  tag severity: 'medium'
  tag gid: 'V-254362'
  tag rid: 'SV-254362r848902_rule'
  tag stig_id: 'WN22-CC-000310'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-57798r848901_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end

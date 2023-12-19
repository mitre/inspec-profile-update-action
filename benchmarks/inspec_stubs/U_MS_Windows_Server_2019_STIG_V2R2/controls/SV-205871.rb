control 'SV-205871' do
  title 'Windows Server 2019 Turning off File Explorer heap termination on corruption must be disabled.'
  desc 'Legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Disabling this feature will prevent this.'
  desc 'check', 'The default behavior is for File Explorer heap termination on corruption to be enabled.

If the registry Value Name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoHeapTerminationOnCorruption

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for File Explorer heap termination on corruption to be disabled.

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Turn off heap termination on corruption" to "Not Configured" or "Disabled".'
  impact 0.3
  ref 'DPMS Target MS Windows Server 2019'
  tag check_id: 'C-6136r355975_chk'
  tag severity: 'low'
  tag gid: 'V-205871'
  tag rid: 'SV-205871r569188_rule'
  tag stig_id: 'WN19-CC-000320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6136r355976_fix'
  tag 'documentable'
  tag legacy: ['V-93261', 'SV-103349']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

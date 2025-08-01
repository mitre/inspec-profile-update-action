control 'SV-48254' do
  title 'Turning off File Explorer heap termination on corruption must be disabled.'
  desc 'Legacy plug-in applications may continue to function when a File Explorer session has become corrupt.  Disabling this feature will prevent this.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoHeapTerminationOnCorruption

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off heap termination on corruption" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44932r1_chk'
  tag severity: 'low'
  tag gid: 'V-15718'
  tag rid: 'SV-48254r2_rule'
  tag stig_id: 'WN08-CC-000090'
  tag gtitle: 'Windows Explorer – Heap Termination'
  tag fix_id: 'F-41389r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

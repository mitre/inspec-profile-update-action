control 'SV-225376' do
  title 'Turning off File Explorer heap termination on corruption must be disabled.'
  desc 'Legacy plug-in applications may continue to function when a File Explorer session has become corrupt.  Disabling this feature will prevent this.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoHeapTerminationOnCorruption

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off heap termination on corruption" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27075r471470_chk'
  tag severity: 'low'
  tag gid: 'V-225376'
  tag rid: 'SV-225376r569185_rule'
  tag stig_id: 'WN12-CC-000090'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-27063r471471_fix'
  tag 'documentable'
  tag legacy: ['SV-53137', 'V-15718']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

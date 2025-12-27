control 'SV-253397' do
  title 'File Explorer heap termination on corruption must be disabled.'
  desc 'Legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Disabling this feature will prevent this.'
  desc 'check', 'The default behavior is for File Explorer heap termination on corruption to be enabled.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoHeapTerminationOnCorruption

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for File Explorer heap termination on corruption to be enabled.

To correct this, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Turn off heap termination on corruption" to "Not Configured" or "Disabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56850r829273_chk'
  tag severity: 'low'
  tag gid: 'V-253397'
  tag rid: 'SV-253397r829275_rule'
  tag stig_id: 'WN11-CC-000220'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-56800r829274_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

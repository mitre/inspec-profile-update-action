control 'SV-88227' do
  title 'Turning off File Explorer heap termination on corruption must be disabled.'
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
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73645r1_chk'
  tag severity: 'low'
  tag gid: 'V-73563'
  tag rid: 'SV-88227r1_rule'
  tag stig_id: 'WN16-CC-000350'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-80013r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

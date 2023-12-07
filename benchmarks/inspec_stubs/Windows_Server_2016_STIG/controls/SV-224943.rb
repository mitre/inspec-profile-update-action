control 'SV-224943' do
  title 'File Explorer shell protocol must run in protected mode.'
  desc 'The shell protocol will limit the set of folders that applications can open when run in protected mode. Restricting files an application can open to a limited set of folders increases the security of Windows.'
  desc 'check', 'The default behavior is for shell protected mode to be turned on for File Explorer.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: PreXPSP2ShellProtocolBehavior

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for shell protected mode to be turned on for File Explorer.

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Turn off shell protocol protected mode" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26634r465731_chk'
  tag severity: 'medium'
  tag gid: 'V-224943'
  tag rid: 'SV-224943r569186_rule'
  tag stig_id: 'WN16-CC-000360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26622r465732_fix'
  tag 'documentable'
  tag legacy: ['SV-88229', 'V-73565']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

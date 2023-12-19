control 'SV-253398' do
  title 'File Explorer shell protocol must run in protected mode.'
  desc 'The shell protocol will limit the set of folders applications can open when run in protected mode. Restricting files an application can open, to a limited set of folders, increases the security of Windows.'
  desc 'check', 'The default behavior is for shell protected mode to be turned on for file explorer.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: PreXPSP2ShellProtocolBehavior

Value Type: REG_DWORD
Value: 0 (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for shell protected mode to be turned on for file explorer.

To correct this, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Turn off shell protocol protected mode" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56851r829276_chk'
  tag severity: 'medium'
  tag gid: 'V-253398'
  tag rid: 'SV-253398r829278_rule'
  tag stig_id: 'WN11-CC-000225'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56801r829277_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-226336' do
  title 'The system must be configured to require case insensitivity for non-Windows subsystems.'
  desc 'This setting controls the behavior of non-Windows subsystems when dealing with the case of arguments or commands.  Case sensitivity could lead to the access of files or commands that must be restricted.  To prevent this from happening, case insensitivity restrictions must be required.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\Kernel\\

Value Name: ObCaseInsensitive

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System objects: Require case insensitivity for non-Windows subsystems" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28038r476852_chk'
  tag severity: 'medium'
  tag gid: 'V-226336'
  tag rid: 'SV-226336r794681_rule'
  tag stig_id: 'WN12-SO-000075'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28026r476853_fix'
  tag 'documentable'
  tag legacy: ['SV-52897', 'V-3385']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

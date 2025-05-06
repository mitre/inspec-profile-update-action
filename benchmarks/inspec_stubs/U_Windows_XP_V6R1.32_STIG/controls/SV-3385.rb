control 'SV-3385' do
  title 'The system is configured to allow case insensitivity.'
  desc 'This setting controls the behavior of non-Windows subsystems when dealing with the case of arguments or commands.  Case sensitivity could lead to the access of files or commands that should be restricted.  To prevent this from happening, case insensitivity restrictions should be required.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “System Object: Require Case Insensitivity for Non-Windows Subsystems” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\Kernel\\

Value Name:  ObCaseInsensitive

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “System Object: Require Case Insensitivity for Non-Windows Subsystems” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-203r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3385'
  tag rid: 'SV-3385r1_rule'
  tag gtitle: 'Case Insensitivity for Non-Windows'
  tag fix_id: 'F-5682r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end

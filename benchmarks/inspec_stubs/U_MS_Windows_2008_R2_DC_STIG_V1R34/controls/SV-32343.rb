control 'SV-32343' do
  title 'The system must be configured to require case insensitivity for non-Windows subsystems.'
  desc 'This setting controls the behavior of non-Windows subsystems when dealing with the case of arguments or commands.  Case sensitivity could lead to the access of files or commands that must be restricted.  To prevent this from happening, case insensitivity restrictions must be required.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "System Objects: Require case insensitivity for non-Windows subsystems" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel\\

Value Name:  ObCaseInsensitive

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "System Objects: Require case insensitivity for non-Windows subsystems" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-60909r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3385'
  tag rid: 'SV-32343r2_rule'
  tag gtitle: 'Case Insensitivity for Non-Windows'
  tag fix_id: 'F-65641r2_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

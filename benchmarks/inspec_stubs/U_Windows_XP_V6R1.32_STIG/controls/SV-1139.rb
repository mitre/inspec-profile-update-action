control 'SV-1139' do
  title 'The option to prevent the password in dial-up networking from being saved is not enabled.'
  desc 'The default Windows configuration enables the option to save the password used to gain access to a remote server using the dial-up networking feature.  With this option enabled, an unauthorized user who gains access to a Windows machine would also have access to remote servers with which the  machine uses dial-up networking to communicate.  Disabling this option will introduce another layer of security and help limit the scope of any security compromise to the local machine.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view.

Navigate to Local Policies -> Security Options.

If the value for “MSS: (DisableSavePassword) Prevent the dial-up password from being saved (recommended)” is not set to  “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\RasMan\\Parameters\\

Value Name:  DisableSavePassword

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (DisableSavePassword) Prevent the dial-up password from being saved (recommended)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-76r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1139'
  tag rid: 'SV-1139r1_rule'
  tag gtitle: 'Dial Up Password Saved'
  tag fix_id: 'F-86r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end

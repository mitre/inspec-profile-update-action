control 'SV-32384' do
  title 'User Account Control will only elevate UIAccess applications that are installed in secure locations'
  desc 'This check verifies whether Windows only allows applications installed in a secure location, such as the Program Files or the Windows\\System32 folders, on the file system to run with elevated privileges.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “User Account Control: Only elevate UIAccess applications that are installed in secure locations” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  EnableSecureUIAPaths

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Only elevate UIAccess applications that are installed in secure locations” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32773r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14239'
  tag rid: 'SV-32384r1_rule'
  tag gtitle: 'UAC - UIAccess Application Elevation'
  tag fix_id: 'F-28845r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end

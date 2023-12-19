control 'SV-213161' do
  title 'Adobe Reader DC must disable the ability to add Trusted Files and Folders.'
  desc "Privileged Locations allow the user to selectively trust files, folders, and hosts to bypass some security restrictions, such as enhanced security and protected view. By default, the user can create privileged locations through the GUI.

Disabling Trusted Files and Folders disables and locks the end user's ability to add folders and files as a privileged location prevents them from assigning trust and thereby exempting that location from enhanced security restrictions."
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown

Value Name: bDisableTrustedFolders
Type: REG_DWORD
Value: 1

If the value for bDisableTrustedFolders is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown

Value Name: bDisableTrustedFolders
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14397r276626_chk'
  tag severity: 'medium'
  tag gid: 'V-213161'
  tag rid: 'SV-213161r557349_rule'
  tag stig_id: 'ARDC-CL-000315'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-14395r276627_fix'
  tag 'documentable'
  tag legacy: ['V-65801', 'SV-80291']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end

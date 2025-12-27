control 'SV-213162' do
  title 'Adobe Reader DC must disable the ability to specify Host-Based Privileged Locations.'
  desc "Privileged Locations allow the user to selectively trust files, folders, and hosts to bypass some security restrictions, such as enhanced security and protected view. By default, the user can create privileged locations through the GUI.

Disabling Host-Based Privileged Locations disables and locks the end user's ability to add hosts as a privileged location prevents them from assigning trust and thereby exempting that location from enhanced security restrictions."
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown

Value Name: bDisableTrustedSites
Type: REG_DWORD
Value: 1

If the value for bDisableTrustedSites is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown

Value Name: bDisableTrustedSites
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14398r276629_chk'
  tag severity: 'medium'
  tag gid: 'V-213162'
  tag rid: 'SV-213162r557349_rule'
  tag stig_id: 'ARDC-CL-000320'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-14396r276630_fix'
  tag 'documentable'
  tag legacy: ['V-65803', 'SV-80293']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end

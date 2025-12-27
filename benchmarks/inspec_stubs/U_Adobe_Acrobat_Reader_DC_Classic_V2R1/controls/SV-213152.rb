control 'SV-213152' do
  title 'Adobe Reader DC must disable Cloud Synchronization.'
  desc 'By default, Adobe online services are tightly integrated in Adobe Reader DC. When the Adobe Cloud synchronization is disabled it prevents the synchronization of desktop preferences across devices on which the user is signed in with an Adobe ID (including phones).'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cServices

Value Name: bTogglePrefsSync
Type: REG_DWORD
Value: 1

If the value for bTogglePrefSync is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cServices

Value Name: bTogglePrefsSync
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14388r276599_chk'
  tag severity: 'medium'
  tag gid: 'V-213152'
  tag rid: 'SV-213152r557349_rule'
  tag stig_id: 'ARDC-CL-000065'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14386r276600_fix'
  tag 'documentable'
  tag legacy: ['SV-80273', 'V-65783']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

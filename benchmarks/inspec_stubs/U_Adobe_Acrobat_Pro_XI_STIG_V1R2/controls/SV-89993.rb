control 'SV-89993' do
  title 'Adobe Acrobat Pro XI Adobe Cloud Synchronization must be disabled.'
  desc 'By default, Adobe online services are tightly integrated in Adobe Acrobat. When the Adobe Cloud synchronization is disabled it prevents the synchronization of desktop preferences across devices on which the user is signed in with an Adobe ID (including phones).'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cServices" is not created by default in the Acrobat Pro XI install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cServices

Value Name: bTogglePrefsSync
Type: REG_DWORD
Value: 1

If the value for bTogglePrefsSync is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cServices" is not created by default in the Acrobat Pro XI install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cServices

Value Name: bTogglePrefsSync
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75097r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75313'
  tag rid: 'SV-89993r1_rule'
  tag stig_id: 'ADBP-XI-001290'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81929r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

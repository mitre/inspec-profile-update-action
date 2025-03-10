control 'SV-213132' do
  title 'Adobe Acrobat Pro DC Continuous Cloud Synchronization must be disabled.'
  desc 'By default, Adobe online services are tightly integrated in Adobe Acrobat. When the Adobe Cloud synchronization is disabled it prevents the synchronization of desktop preferences across devices on which the user is signed in with an Adobe ID (including phones).'
  desc 'check', "Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown\\cServices

Value Name: bTogglePrefsSync
Type: REG_DWORD
Value: 1

If the value for bTogglePrefsSync is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'Cloud Synchronization' must be set to 'Disabled'."
  desc 'fix', "Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown\\cServices

Value Name: bTogglePrefsSync
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'Cloud Synchronization' to 'Disabled'."
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14369r766548_chk'
  tag severity: 'medium'
  tag gid: 'V-213132'
  tag rid: 'SV-213132r766550_rule'
  tag stig_id: 'AADC-CN-001290'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14367r766549_fix'
  tag 'documentable'
  tag legacy: ['SV-94095', 'V-79389']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

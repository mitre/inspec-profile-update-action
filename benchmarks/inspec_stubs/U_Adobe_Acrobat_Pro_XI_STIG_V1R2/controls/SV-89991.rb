control 'SV-89991' do
  title 'Adobe Acrobat Pro XI third-party web connectors must be disabled.'
  desc 'Third-party connectors include services such as Dropbox and Google Drive. When third-party web connectors are disabled, it prevents access to third-party services for file storage. Allowing access to online storage services introduces the risk of data loss or data exfiltration.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cServices" is not created by default in the Acrobat Pro XI install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cServices

Value Name: bToggleWebConnectors
Type: REG_DWORD
Value: 1

If the value for bToggleWebConnectors is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cServices" is not created by default in the Acrobat Pro XI install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cServices

Value Name: bToggleWebConnectors
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75095r2_chk'
  tag severity: 'low'
  tag gid: 'V-75311'
  tag rid: 'SV-89991r1_rule'
  tag stig_id: 'ADBP-XI-001300'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81927r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

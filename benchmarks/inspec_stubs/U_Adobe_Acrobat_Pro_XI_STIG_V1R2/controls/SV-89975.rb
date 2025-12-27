control 'SV-89975' do
  title 'Adobe Acrobat Pro XI must disable the ability to store files on Acrobat.com.'
  desc 'Adobe Acrobat Pro XI provides the ability to store PDF files on Adobe.com servers. Allowing users to store files on non-DoD systems introduces risk of data compromise.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro XI install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cCloud

Value Name: bDisableADCFileStore
Type: REG_DWORD
Value: 1

If the value for bDisableADCFileStore is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro XI install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cCloud

Value Name: bDisableADCFileStore
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75079r3_chk'
  tag severity: 'medium'
  tag gid: 'V-75295'
  tag rid: 'SV-89975r1_rule'
  tag stig_id: 'ADBP-XI-001285'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81911r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

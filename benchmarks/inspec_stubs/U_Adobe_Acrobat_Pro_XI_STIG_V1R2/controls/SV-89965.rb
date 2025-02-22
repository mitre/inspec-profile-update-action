control 'SV-89965' do
  title 'Adobe Acrobat Pro XI Protected Mode must be enabled.'
  desc "Protected Mode is a “sandbox” that is essentially a read-only mode.

When enabled, Acrobat allows the execution environment of untrusted PDF's and the processes the PDF may invoke but also presumes all PDFs are potentially malicious and confines processing to a restricted sandbox."
  desc 'check', 'Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: bProtectedMode
Type: REG_DWORD
Value: 1

If the value for bProtectedMode is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: bProtectedMode
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75069r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75285'
  tag rid: 'SV-89965r1_rule'
  tag stig_id: 'ADBP-XI-001010'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-81901r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end

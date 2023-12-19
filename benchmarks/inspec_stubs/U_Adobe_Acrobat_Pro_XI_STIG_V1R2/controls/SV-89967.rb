control 'SV-89967' do
  title 'Adobe Acrobat Pro XI Protected View must be enabled.'
  desc "Protected View is a “super-sandbox” that is essentially a read-only mode. When enabled, Acrobat strictly confines the execution environment of untrusted PDF's and the processes the PDF may invoke. Acrobat also assumes all PDFs are potentially malicious and confines processing to a restricted sandbox.

When the PDF is opened, the user is presented with the option to trust the document. When the user chooses to trust the document, all features are enabled, this action assigns trust to the document and adds the document to the users’ list of Privileged Locations."
  desc 'check', 'Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: iProtectedView
Type: REG_DWORD
Value: 2

If the value for iProtectedView is not set to “2” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: iProtectedView
Type: REG_DWORD
Value: 2'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75071r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75287'
  tag rid: 'SV-89967r1_rule'
  tag stig_id: 'ADBP-XI-001015'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-81903r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end

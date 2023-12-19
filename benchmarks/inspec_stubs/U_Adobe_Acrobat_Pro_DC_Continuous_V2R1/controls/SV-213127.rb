control 'SV-213127' do
  title 'Adobe Acrobat Pro DC Continuous Protected Mode must be enabled.'
  desc "Protected Mode is a “sandbox” that is essentially a read-only mode.  When enabled, Acrobat allows the execution environment of untrusted PDF's and the processes the PDF may invoke but also presumes all PDFs are potentially malicious and confines processing to a restricted sandbox."
  desc 'check', "Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown

Value Name: bProtectedMode
Type: REG_DWORD
Value: 1

If the value for bProtectedMode is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > 'Protected Mode' must be set to 'Enabled'."
  desc 'fix', "Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown

Value Name: bProtectedMode
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > 'Protected Mode' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14364r766536_chk'
  tag severity: 'medium'
  tag gid: 'V-213127'
  tag rid: 'SV-213127r766538_rule'
  tag stig_id: 'AADC-CN-001010'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-14362r766537_fix'
  tag 'documentable'
  tag legacy: ['SV-94085', 'V-79379']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end

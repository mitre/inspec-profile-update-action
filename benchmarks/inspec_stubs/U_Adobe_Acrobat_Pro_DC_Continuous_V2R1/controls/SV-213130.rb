control 'SV-213130' do
  title 'Adobe Acrobat Pro DC Continuous Default Handler changes must be disabled.'
  desc 'Acrobat Pro allows users to change the version of Acrobat Pro that is used to read PDF files. This is a risk if multiple versions of Acrobat are installed on the system and the other version has dissimilar security configurations or known vulnerabilities. When the Default PDF Handler is disabled, the end users will not be able to change the default PDF viewer.'
  desc 'check', "Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown

Value Name: bDisablePDFHandlerSwitching
Type: REG_DWORD
Value: 1

If the value for bDisablePDFHandlerSwitching is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Edit > Preferences > General > Verify the 'Select As Default PDF Handler' option is greyed out (locked).  If the option is not greyed out, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > General > 'Disable PDF handler switching' must be set to 'Enabled'."
  desc 'fix', "Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown

Value Name: bDisablePDFHandlerSwitching
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > General > 'Disable PDF handler switching' to 'Enabled'."
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14367r766542_chk'
  tag severity: 'low'
  tag gid: 'V-213130'
  tag rid: 'SV-213130r766544_rule'
  tag stig_id: 'AADC-CN-001280'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-14365r766543_fix'
  tag 'documentable'
  tag legacy: ['SV-94091', 'V-79385']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

control 'SV-94087' do
  title 'Adobe Acrobat Pro DC Continuous Protected View must be enabled.'
  desc "Protected View is a “super-sandbox” that is essentially a read-only mode. When enabled, Acrobat strictly confines the execution environment of untrusted PDF's and the processes the PDF may invoke. Acrobat also assumes all PDFs are potentially malicious and confines processing to a restricted sandbox. When the PDF is opened, the user is presented with the option to trust the document. When the user chooses to trust the document, all features are enabled, this action assigns trust to the document and adds the document to the users’ list of Privileged Locations."
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown

Value Name: iProtectedView
Type: REG_DWORD
Value: 2

If the value for iProtectedView is not set to “2” and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Edit > Preferences > Security (Enhanced) > In the 'Protected View' section, verify the radio button for 'All files' is checked and greyed out (locked). If the button is not checked nor greyed out, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > Security (Enhanced) > 'Protected View' must be set to 'Enabled' and 'All files' selected in the drop down box.  

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown

Value Name: iProtectedView
Type: REG_DWORD
Value: 2

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > Security (Enhanced) > 'Protected View' to 'Enabled' and select 'All files' in the drop down box.  

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro DC Continuous'
  tag check_id: 'C-78995r3_chk'
  tag severity: 'medium'
  tag gid: 'V-79381'
  tag rid: 'SV-94087r1_rule'
  tag stig_id: 'AADC-CN-001015'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-86153r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end

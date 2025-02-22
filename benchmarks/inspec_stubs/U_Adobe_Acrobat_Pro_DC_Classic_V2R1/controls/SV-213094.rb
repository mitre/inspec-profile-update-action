control 'SV-213094' do
  title 'Adobe Acrobat Pro DC Classic Enhanced Security for browser mode must be enabled.'
  desc 'Enhanced Security (ES) is a sandbox capability that restricts access to system resources and prevents PDF cross domain access. ES can be configured in two modes: Standalone mode is when Acrobat opens the desktop PDF client. ES Browser mode is when a PDF is opened via the browser plugin. When Enhanced Security is enabled and a PDF file tries to complete a restricted action from an untrusted location, a security warning must appear. Enhanced Security "hardens" the application against risky actions. It prevents cross domain access, prohibits script and data injection, blocks stream access to XObjects, silent printing, and execution of high privilege JavaScript.'
  desc 'check', %q(Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown

Value Name: bEnhancedSecurityInBrowser
Type: REG_DWORD
Value: 1

If the value for bEnhancedSecurityInBrowser is not set to "1" and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > Security (Enhanced) > 'Enable Enhanced Security In Browser' must be set to 'Enabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown

Value Name: bEnhancedSecurityInBrowser
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > Security (Enhanced) > 'Enable Enhanced Security In Browser' to 'Enabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14332r478107_chk'
  tag severity: 'medium'
  tag gid: 'V-213094'
  tag rid: 'SV-213094r557504_rule'
  tag stig_id: 'AADC-CL-000210'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-14330r478108_fix'
  tag 'documentable'
  tag legacy: ['SV-94817', 'V-80113']
  tag cci: ['CCI-001695', 'CCI-002530']
  tag nist: ['SC-18 (3)', 'SC-39']
end

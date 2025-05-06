control 'SV-94067' do
  title 'Adobe Acrobat Pro DC Continuous Enhanced Security for browser mode must be enabled.'
  desc 'Enhanced Security (ES) is a sandbox capability that restricts access to system resources and prevents PDF cross domain access. ES can be configured in two modes: Standalone mode is when Acrobat opens the desktop PDF client. ES Browser mode is when a PDF is opened via the browser plugin. When Enhanced Security is enabled and a PDF file tries to complete a restricted action from an untrusted location, a security warning must appear.Enhanced Security “hardens” the application against risky actions. It prevents cross domain access, prohibits script and data injection, blocks stream access to XObjects, silent printing, and execution of high privilege JavaScript.'
  desc 'check', %q(Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown

Value Name: bEnhancedSecurityInBrowser
Type: REG_DWORD
Value: 1

If the value for bEnhancedSecurityInBrowser is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > Security (Enhanced) > 'Enable Enhanced Security In Browser' must be set to 'Enabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown

Value Name: bEnhancedSecurityInBrowser
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > Security (Enhanced) > 'Enable Enhanced Security In Browser' to 'Enabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro DC Continuous'
  tag check_id: 'C-78975r4_chk'
  tag severity: 'medium'
  tag gid: 'V-79361'
  tag rid: 'SV-94067r1_rule'
  tag stig_id: 'AADC-CN-000210'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-86133r4_fix'
  tag 'documentable'
  tag cci: ['CCI-001695', 'CCI-002530']
  tag nist: ['SC-18 (3)', 'SC-39']
end

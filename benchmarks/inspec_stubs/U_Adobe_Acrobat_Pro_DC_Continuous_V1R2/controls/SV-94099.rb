control 'SV-94099' do
  title 'Adobe Acrobat Pro DC Continuous third-party web connectors must be disabled.'
  desc 'Third-party connectors include services such as Dropbox and Google Drive. When third-party web connectors are disabled, it prevents access to third-party services for file storage. Allowing access to online storage services introduces the risk of data loss or data exfiltration.'
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices

Value Name: bToggleWebConnectors
Type: REG_DWORD
Value: 1

If the value for bToggleWebConnectors is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'Third-party web connectors' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices

Value Name: bToggleWebConnectors
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'Third-party web connectors' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro DC Continuous'
  tag check_id: 'C-79007r3_chk'
  tag severity: 'low'
  tag gid: 'V-79393'
  tag rid: 'SV-94099r1_rule'
  tag stig_id: 'AADC-CN-001300'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-86165r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

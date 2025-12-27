control 'SV-213110' do
  title 'Adobe Acrobat Pro DC Classic third-party web connectors must be disabled.'
  desc 'Third-party connectors include services such as Dropbox and Google Drive. When third-party web connectors are disabled, it prevents access to third-party services for file storage. Allowing access to online storage services introduces the risk of data loss or data exfiltration.'
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cServices

Value Name: bToggleWebConnectors
Type: REG_DWORD
Value: 1

If the value for bToggleWebConnectors is not set to "1" and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Classic > Preferences > 'Third-party web connectors' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cServices

Value Name: bToggleWebConnectors
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Classic > Preferences > 'Third-party web connectors' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14348r478149_chk'
  tag severity: 'low'
  tag gid: 'V-213110'
  tag rid: 'SV-213110r557504_rule'
  tag stig_id: 'AADC-CL-001300'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14346r478150_fix'
  tag 'documentable'
  tag legacy: ['SV-94849', 'V-80145']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

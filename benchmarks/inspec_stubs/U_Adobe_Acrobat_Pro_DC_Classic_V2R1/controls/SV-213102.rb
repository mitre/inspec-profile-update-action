control 'SV-213102' do
  title 'Adobe Acrobat Pro DC Classic periodic downloading of Adobe European certificates must be disabled.'
  desc "By default, the user can update Adobe European certificates from an Adobe server through the GUI.   When updating Adobe European certificates is disabled, it prevents the automatic download and installation of certificates and disables and locks the end user's ability to download those certificates."
  desc 'check', %q(Verify the following registry configuration:

Note: The Key Name "cEUTLDownload" is not created by default in the Acrobat Pro DC install and must be created.

Using the Registry Editor, navigate to the following: HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\2015\Security\cDigSig\cEUTLDownload

Value Name: bLoadSettingsFromURL
Type: REG_DWORD
Value: 0

If the value for bLoadSettingsFromURL is not set to "0" and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Edit > Preferences > Trust Manager > In the 'Automatic European Union Trusted Lists (EUTL) updates' section > Verify the 'Load trusted certificates from an Adobe EUTL server' is not checked.  If the box is checked, this is a finding.

Admin Template path: User Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > Trust Manager > 'Load trusted certificates from an Adobe EUTL server' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Note: The Key Name "cEUTLDownload" is not created by default in the Acrobat Pro DC install and must be created.

Registry Hive:
HKEY_CURRENT_USER
Registry Path:
\Software\Adobe\Adobe Acrobat\2015\Security\cDigSig\cEUTLDownload

Value Name: bLoadSettingsFromURL
Type: REG_DWORD
Value: 0

Configure the policy value for User Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > Trust Manager > 'Load trusted certificates from an Adobe EUTL server' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14340r478128_chk'
  tag severity: 'low'
  tag gid: 'V-213102'
  tag rid: 'SV-213102r557504_rule'
  tag stig_id: 'AADC-CL-000990'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-14338r478129_fix'
  tag 'documentable'
  tag legacy: ['V-80129', 'SV-94833']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

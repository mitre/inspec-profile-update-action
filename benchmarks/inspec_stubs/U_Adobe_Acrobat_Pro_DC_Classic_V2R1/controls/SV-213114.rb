control 'SV-213114' do
  title 'Adobe Acrobat Pro DC Classic Periodic downloading of Adobe certificates must be disabled.'
  desc "By default, the user can update Adobe certificates from an Adobe server through the GUI. When updating Adobe certificates is disabled, it prevents the automatic download and installation of certificates and disables and locks the end user's ability to download those certificates."
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\2015\Security\cDigSig\cAdobeDownload

Value Name: bLoadSettingsFromURL
Type: REG_DWORD
Value: 0

If the value for bLoadSettingsFromURL is not set to "0" and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Edit > Preferences > Trust Manager > In the 'Automatic Adobe Approved Trust List (AATL) Updates' section > verify the 'Load trusted certificates from an Adobe AATL server' is not checked.  If the box is checked, this is a finding.

Admin Template path: User Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > Trust Manager > 'Load trusted certificates from an Adobe AATL server' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_CURRENT_USER
Registry Path:
\Software\Adobe\Adobe Acrobat\2015\Security\cDigSig\cAdobeDownload

Value Name: bLoadSettingsFromURL
Type: REG_DWORD
Value: 0

Configure the policy value for User Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > Trust Manager > 'Load trusted certificates from an Adobe AATL server' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14352r478161_chk'
  tag severity: 'low'
  tag gid: 'V-213114'
  tag rid: 'SV-213114r557504_rule'
  tag stig_id: 'AADC-CL-001320'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-14350r478162_fix'
  tag 'documentable'
  tag legacy: ['SV-94857', 'V-80153']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

control 'SV-213138' do
  title 'Adobe Acrobat Pro DC Continuous Periodic downloading of Adobe certificates must be disabled.'
  desc "By default, the user can update Adobe certificates from an Adobe server through the GUI. When updating Adobe certificates is disabled, it prevents the automatic download and installation of certificates and disables and locks the end user's ability to download those certificates."
  desc 'check', "Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_CURRENT_USER\\Software\\Adobe\\Adobe Acrobat\\DC\\Security\\cDigSig\\cAdobeDownload

Value Name: bLoadSettingsFromURL
Type: REG_DWORD
Value: 0

If the value for bLoadSettingsFromURL is not set to “0” and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Edit > Preferences > Trust Manager > In the 'Automatic Adobe Approved Trust List (AATL) Updates' section > verify the 'Load trusted certificates from an Adobe AATL server' is not checked.  If the box is checked, this is a finding.

Admin Template path: User Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > Trust Manager > 'Load trusted certificates from an Adobe AATL server' must be set to 'Disabled'."
  desc 'fix', "Configure the following registry value:

Registry Hive:
HKEY_CURRENT_USER
Registry Path:
\\Software\\Adobe\\Adobe Acrobat\\DC\\Security\\cDigSig\\cAdobeDownload

Value Name: bLoadSettingsFromURL
Type: REG_DWORD
Value: 0

Configure the policy value for User Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > Trust Manager > 'Load trusted certificates from an Adobe AATL server' to 'Disabled'."
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14375r766566_chk'
  tag severity: 'low'
  tag gid: 'V-213138'
  tag rid: 'SV-213138r766568_rule'
  tag stig_id: 'AADC-CN-001320'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-14373r766567_fix'
  tag 'documentable'
  tag legacy: ['SV-94107', 'V-79401']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

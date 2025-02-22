control 'SV-80165' do
  title 'Adobe Reader DC must disable periodical uploading of Adobe certificates.'
  desc "By default, the user can update Adobe certificates from an Adobe server through the GUI.

When uploading Adobe certificates is disabled, it prevents the automatic download and installation of certificates and disables and locks the end user's ability to upload those certificates."
  desc 'check', 'Verify the following registry configuration:

Note: The Key Names "cDigSig" and "cAdobeDownload" are not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_CURRENT_USER\\Software\\Adobe\\Acrobat Reader\\DC\\Security\\cDigSig\\cAdobeDownload

Value Name: bLoadSettingsFromURL 
Type: REG_DWORD
Value: 0

If the value for bLoadSettingsFromURL is not set to “0” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Names "cDigSig" and "cAdobeDownload" are not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Adobe\\Acrobat Reader\\DC\\Security\\cDigSig\\cAdobeDownload

Value Name: bLoadSettingsFromURL 
Type: REG_DWORD
Value: 0'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous'
  tag check_id: 'C-66249r2_chk'
  tag severity: 'low'
  tag gid: 'V-65675'
  tag rid: 'SV-80165r1_rule'
  tag stig_id: 'ARDC-CN-000335'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-71635r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

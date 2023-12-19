control 'SV-89961' do
  title 'Adobe Acrobat Pro XI periodic downloading of Adobe European certificates must be disabled.'
  desc "By default, the user can update Adobe European certificates from an Adobe server through the GUI.

When updating Adobe European certificates is disabled, it prevents the automatic download and installation of certificates and disables and locks the end user's ability to download those certificates."
  desc 'check', 'Verify the following registry configuration:

Note: The Key Names "cDigSig" and "cEUTLDownload" are not created by default in the Acrobat Pro XI install and must be created.

Using the Registry Editor, navigate to the following: HKEY_CURRENT_USER\\Software\\Adobe\\Adobe Acrobat\\11.0\\Security\\cDigSig\\cEUTLDownload

Value Name: bLoadSettingsFromURL
Type: REG_DWORD
Value: 0

If the value for bLoadSettingsFromURL is not set to “0” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Names "cDigSig" and "cEUTLDownload" are not created by default in the Acrobat Pro XI install and must be created.

Registry Hive:
HKEY_CURRENT_USER
Registry Path:
\\Software\\Adobe\\Adobe Acrobat\\11.0\\Security\\cDigSig\\cEUTLDownload

Value Name: bLoadSettingsFromURL
Type: REG_DWORD
Value: 0'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75065r2_chk'
  tag severity: 'low'
  tag gid: 'V-75281'
  tag rid: 'SV-89961r1_rule'
  tag stig_id: 'ADBP-XI-000990'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-81897r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

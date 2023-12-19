control 'SV-53241' do
  title 'Add-ins to Office applications must be signed by a Trusted Publisher.'
  desc "Office 2013 applications do not check the digital signature on application add-ins before opening them.  Disabling or not configuring this setting may allow an application to load a dangerous add-in.  As a result, malicious code could become active on the user's computer or the network."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2013 -> Security -> Trust Center "Require that application add-ins are signed by Trusted Publisher" is set to "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\publisher\\security

Criteria: If the value RequireAddinSig is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2013 -> Security -> Trust Center "Require that application add-ins are signed by Trusted Publisher" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Publisher 2013'
  tag check_id: 'C-47548r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26589'
  tag rid: 'SV-53241r2_rule'
  tag stig_id: 'DTOO127'
  tag gtitle: 'DTOO127 - Add-ins are signed by Trusted Publisher'
  tag fix_id: 'F-46168r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

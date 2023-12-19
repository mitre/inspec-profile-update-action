control 'SV-33850' do
  title 'Application add-ins must be signed by Trusted Publisher.'
  desc 'Office 2010 applications do not check the digital signature on application add-ins before opening them.  Disabling or not configuring this setting may allow an application to load a dangerous add-in.  As a result, malicious code could become active on user computers or the network.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center “Require that application add-ins are signed by Trusted Publisher” must be set to “Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\security

Criteria: If the value RequireAddinSig is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center “Require that application add-ins are signed by Trusted Publisher” to “Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-34192r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26589'
  tag rid: 'SV-33850r1_rule'
  tag stig_id: 'DTOO127 - Excel'
  tag gtitle: 'DTOO127 - Add-ins are signed by Trusted Publisher'
  tag fix_id: 'F-29886r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

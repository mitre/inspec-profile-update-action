control 'SV-111583' do
  title 'The Windows Explorer Preview pane must be disabled for Windows Server 2008.'
  desc 'A known vulnerability in Windows could allow the execution of malicious code by either opening a compromised document or viewing it in the Windows Preview pane.

Organizations must disable the Windows Preview pane and Windows Detail pane.'
  desc 'check', 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer

Value Name: NoPreviewPane

Value Type: REG_DWORD

Value: 1

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer

Value Name: NoReadingPane

Value Type: REG_DWORD

Value: 1'
  desc 'fix', 'Ensure the following settings are configured for Windows Server 2008 locally or applied through group policy. 

Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> Windows Explorer >> Explorer Frame Pane "Turn off Preview Pane" to "Enabled".

Configure the policy value for User Configuration >> Administrative Templates >> Windows Components Windows Explorer >> Explorer Frame Pane "Turn on or off details pane" to "Enabled" and “Configure details pane” to “Always hide”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-101371r4_chk'
  tag severity: 'medium'
  tag gid: 'V-102633'
  tag rid: 'SV-111583r1_rule'
  tag stig_id: 'WIN00-000191'
  tag gtitle: 'WIN00-000191'
  tag fix_id: 'F-108167r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

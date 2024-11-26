control 'SV-220861' do
  title 'The Windows Explorer Preview pane must be disabled for Windows 10.'
  desc 'A known vulnerability in Windows 10 could allow the execution of malicious code by either opening a compromised document or viewing it in the Windows Preview pane.

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
  desc 'fix', 'Ensure the following settings are configured for Windows 10 locally or applied through group policy. 

Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> File Explorer >> Explorer Frame Pane "Turn off Preview Pane" to "Enabled".

Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> File Explorer >> Explorer Frame Pane "Turn on or off details pane" to "Enabled" and "Configure details pane" to "Always hide".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22576r603220_chk'
  tag severity: 'medium'
  tag gid: 'V-220861'
  tag rid: 'SV-220861r877377_rule'
  tag stig_id: 'WN10-CC-000328'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-22565r603223_fix'
  tag 'documentable'
  tag legacy: ['SV-111563', 'V-102617']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

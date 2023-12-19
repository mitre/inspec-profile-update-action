control 'SV-226233' do
  title 'The Windows Explorer Preview pane must be disabled for Windows 2012.'
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
  desc 'fix', 'Ensure the following settings are configured for Windows 2012 locally or applied through group policy.
 
Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> File Explorer >> Explorer Frame Pane "Turn off Preview Pane" to "Enabled".

Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> File Explorer >> Explorer Frame Pane "Turn on or off details pane" to "Enabled" and "Configure details pane" to "Always hide".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27935r476543_chk'
  tag severity: 'medium'
  tag gid: 'V-226233'
  tag rid: 'SV-226233r794560_rule'
  tag stig_id: 'WN12-CC-000142'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-27923r476544_fix'
  tag 'documentable'
  tag legacy: ['SV-111569', 'V-102619']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-235763' do
  title 'Microsoft Defender SmartScreen must be enabled.'
  desc 'This policy setting configures Microsoft Defender SmartScreen, which provides warning messages to help protect  users from potential phishing scams and malicious software. By default, Microsoft Defender SmartScreen is turned on.

If this setting is enabled, Microsoft Defender SmartScreen is turned on.

If this setting is disabled, Microsoft Defender SmartScreen is turned off.

If this setting is not configured, users can choose whether to use Microsoft Defender SmartScreen.

This policy is available only on Windows instances that are joined to a Microsoft Active Directory domain, Windows 10 Pro or Enterprise instances that enrolled for device management, or macOS instances that are that are managed via MDM or joined to a domain via MCX.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/SmartScreen settings/Configure Microsoft Defender SmartScreen" must be set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "SmartScreenEnabled" is not set to "REG_DWORD = 1", this is a finding.

If this machine is on SIPRNet, this is Not Applicable.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/SmartScreen settings/Configure Microsoft Defender SmartScreen" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38982r766866_chk'
  tag severity: 'medium'
  tag gid: 'V-235763'
  tag rid: 'SV-235763r766868_rule'
  tag stig_id: 'EDGE-00-000050'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38945r766867_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

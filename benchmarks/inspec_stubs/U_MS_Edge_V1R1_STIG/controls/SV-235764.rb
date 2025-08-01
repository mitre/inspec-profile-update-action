control 'SV-235764' do
  title 'Microsoft Defender SmartScreen must be configured to block potentially unwanted apps.'
  desc 'This policy setting configures blocking for potentially unwanted apps with Microsoft Defender SmartScreen. Potentially unwanted app blocking with Microsoft Defender SmartScreen provides warning messages to help protect users from adware, coin miners, bundleware, and other low-reputation apps that are hosted by websites. Potentially unwanted app blocking with Microsoft Defender SmartScreen is turned off by default.

If this setting is enabled, potentially unwanted app blocking with Microsoft Defender SmartScreen is turned on.

If this setting is disabled, potentially unwanted app blocking with Microsoft Defender SmartScreen is turned off.

If this setting is not configured, users can choose whether to use potentially unwanted app blocking with Microsoft Defender SmartScreen.

This policy is available only on Windows instances that are joined to a Microsoft Active Directory domain, Windows 10 Pro or Enterprise instances that enrolled for device management, or macOS instances that are managed via MDM or joined to a domain via MCX.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/SmartScreen settings/Configure Microsoft Defender SmartScreen to block potentially unwanted apps" must be set to "enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\Recommended

If the value for SmartScreenPuaEnabled is not set to "REG_DWORD = 1", this is a finding.

If this machine is on SIPRNet, this is Not Applicable.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/SmartScreen settings/Configure Microsoft Defender SmartScreen to block potentially unwanted apps" to "enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38983r626488_chk'
  tag severity: 'medium'
  tag gid: 'V-235764'
  tag rid: 'SV-235764r626523_rule'
  tag stig_id: 'EDGE-00-000051'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38946r626489_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

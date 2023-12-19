control 'SV-253422' do
  title 'Windows 11 must be configured to prevent Windows apps from being activated by voice while the system is locked.'
  desc 'Allowing Windows apps to be activated by voice from the lock screen could allow for unauthorized use. Requiring logon will ensure the apps are only used by authorized personnel.'
  desc 'check', 'The setting is NA when the "Allow voice activation" policy is configured to disallow applications to be activated with voice for all users.
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\\

Value Name: LetAppsActivateWithVoiceAboveLock

Type: REG_DWORD
Value: 0x00000002 (2)

If the following registry value exists and is configured as specified, requirement is NA: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\\

Value Name: LetAppsActivateWithVoice

Type: REG_DWORD
Value: 0x00000002 (2)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App Privacy >> "Let Windows apps activate with voice while the system is locked" to "Enabled" with Default for all Apps: set to Force Deny. 

The requirement is NA if the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App Privacy >> "Let Windows apps activate with voice" is configured to "Enabled" with Default for all Apps: set to Force Deny.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56875r829348_chk'
  tag severity: 'medium'
  tag gid: 'V-253422'
  tag rid: 'SV-253422r829350_rule'
  tag stig_id: 'WN11-CC-000365'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-56825r829349_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end

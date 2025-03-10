control 'SV-235762' do
  title 'Messaging hosts that are used must be installed with administrative privileges.'
  desc 'If the policy is set to "enabled" or is unset, Microsoft Edge can use native messaging hosts installed at the user level.

If the policy is set to "disabled", Microsoft Edge can only use these hosts if they are installed at the system level.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Native Messaging/Allow user-level native messaging hosts (installed without admin permissions)" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "NativeMessagingUserLevelHosts" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Native Messaging/Allow user-level native messaging hosts (installed without admin permissions)" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38981r626542_chk'
  tag severity: 'medium'
  tag gid: 'V-235762'
  tag rid: 'SV-235762r626543_rule'
  tag stig_id: 'EDGE-00-000049'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38944r626541_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

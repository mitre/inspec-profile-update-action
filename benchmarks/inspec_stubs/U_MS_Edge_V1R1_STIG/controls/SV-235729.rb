control 'SV-235729' do
  title 'Search suggestions must be disabled.'
  desc 'Enables web search suggestions in the Microsoft Edge Address Bar and Auto-Suggest List, and prevents users from changing this policy.

If this policy is enabled, web search suggestions are used.

If this policy is disabled, web search suggestions are never used; however, local history and local favorites suggestions still appear. If this policy is disabled, neither the typed characters nor the URLs visited will be included in telemetry to Microsoft.

If this policy is not set, search suggestions are enabled but the user can change that.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable search suggestions" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\Recommended

If the value for "SearchSuggestEnabled" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable search suggestions" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38948r626383_chk'
  tag severity: 'medium'
  tag gid: 'V-235729'
  tag rid: 'SV-235729r626523_rule'
  tag stig_id: 'EDGE-00-000012'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38911r626384_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

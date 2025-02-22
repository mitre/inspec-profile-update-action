control 'SV-235739' do
  title 'Importing of search engine settings must be disabled.'
  desc 'Allows users to import search engine settings from another browser into Microsoft Edge.

If this policy is enabled, the option to import search engine settings is automatically selected.

If this policy is disabled, search engine settings are not imported at first run, and users cannot import them manually.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of search engine settings" must be set to "disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportSearchEngine" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of search engine settings" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38958r626413_chk'
  tag severity: 'medium'
  tag gid: 'V-235739'
  tag rid: 'SV-235739r626523_rule'
  tag stig_id: 'EDGE-00-000022'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38921r626414_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

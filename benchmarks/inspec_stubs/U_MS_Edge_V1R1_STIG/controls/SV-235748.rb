control 'SV-235748' do
  title 'Personalization of ads, search, and news by sending browsing history to Microsoft must be disabled.'
  desc "This policy prevents Microsoft from collecting a user's Microsoft Edge browsing history to be used for personalizing advertising, search, news and other Microsoft services.

This setting is only available for users with a Microsoft account. This setting is not available for child accounts or enterprise accounts.

If this policy is disabled, users cannot change or override the setting. If this policy is enabled or not configured, Microsoft Edge will default to the user's preference."
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow personalization of ads, search and news by sending browsing history to Microsoft" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "PersonalizationReportingEnabled" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow personalization of ads, search and news by sending browsing history to Microsoft" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38967r626440_chk'
  tag severity: 'medium'
  tag gid: 'V-235748'
  tag rid: 'SV-235748r626523_rule'
  tag stig_id: 'EDGE-00-000031'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38930r626441_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

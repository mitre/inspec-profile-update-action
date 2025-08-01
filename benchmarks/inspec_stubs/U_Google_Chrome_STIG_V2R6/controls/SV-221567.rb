control 'SV-221567' do
  title 'The Password Manager must be disabled.'
  desc 'Enables saving passwords and using saved passwords in Google Chrome. Malicious sites may take advantage of this feature by using hidden fields gain access to the stored information. If you enable this setting, users can have Google Chrome memorize passwords and provide them automatically the next time they log in to a site. If you disable this setting, users are not able to save passwords or use already saved passwords. If you enable or disable this setting, users cannot change or override this setting in Google Chrome. If this policy is left not set, this will be enabled but the user will be able to change it. ListPassword manager should not be used as it stores passwords locally.'
  desc 'check', 'Universal method:           
   1. In the omnibox (address bar) type chrome://policy           
   2. If PasswordManagerEnabled is not displayed under the Policy Name column or it is not set to false under the Policy Value column, then this is a finding.

Windows method:
   1. Start regedit
   2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
   3. If the PasswordManagerEnabled value name does not exist or its value data is not set to 0, then this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with gpedit.msc 
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Password Manager\\
Policy Name: Enable Saving Passwords to the Password Manager
Policy State: Disabled
Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23282r415828_chk'
  tag severity: 'medium'
  tag gid: 'V-221567'
  tag rid: 'SV-221567r615937_rule'
  tag stig_id: 'DTBC-0011'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23271r415829_fix'
  tag 'documentable'
  tag legacy: ['SV-57575', 'V-44741']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

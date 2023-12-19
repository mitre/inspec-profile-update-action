control 'SV-221566' do
  title 'Default search provider must be enabled.'
  desc 'Policy enables the use of a default search provider. If you enable this setting, a default search is performed when the user types text in the omnibox that is not a URL. You can specify the default search provider to be used by setting the rest of the default search policies. If these are left empty, the user can choose the default provider. If you disable this setting, no search is performed when the user enters non-URL text in the omnibox. If you enable or disable this setting, users cannot change or override this setting in Google Chrome. If this policy is left not set, the default search provider is enabled, and the user will be able to set the search provider list.'
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy 
 2. If DefaultSearchProviderEnabled is not displayed under the Policy Name column or it is not set to true under the Policy Value column, then this is a finding.

Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the DefaultSearchProviderEnabled value name does not exist or its value data is not set to 1, then this is a finding.

Note: This policy will only display in the chrome://policy tab on domain joined systems. On standalone systems, the policy will not display.'
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Default search provider\\
    Policy Name: Enable the default search provider
    Policy State: Enabled
    Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23281r415825_chk'
  tag severity: 'medium'
  tag gid: 'V-221566'
  tag rid: 'SV-221566r615937_rule'
  tag stig_id: 'DTBC-0009'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23270r415826_fix'
  tag 'documentable'
  tag legacy: ['SV-57571', 'V-44737']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

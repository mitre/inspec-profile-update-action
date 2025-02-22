control 'SV-221576' do
  title 'Search suggestions must be disabled.'
  desc "Search suggestion should be disabled as it could lead to searches being conducted that were never intended to be made. Enables search suggestions in Google Chrome's omnibox and prevents users from changing this setting. If you enable this setting, search suggestions are used. If you disable this setting, search suggestions are never used. If you enable or disable this setting, users cannot change or override this setting in Google Chrome. If this policy is left not set, this will be enabled but the user will be able to change it."
  desc 'check', 'Universal method:        
   1. In the omnibox (address bar) type chrome://policy        
   2. If SearchSuggestEnabled is not displayed under the Policy Name column or it is not set to false under the Policy Value column, then this is a finding.

Windows method:
   1. Start regedit
   2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
   3. If the SearchSuggestEnabled value name does not exist or its value data is not set to 0, then this is a finding.'
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
    Policy Name: Enable search suggestions
    Policy State: Disabled
    Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23291r415855_chk'
  tag severity: 'medium'
  tag gid: 'V-221576'
  tag rid: 'SV-221576r615937_rule'
  tag stig_id: 'DTBC-0027'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23280r415856_fix'
  tag 'documentable'
  tag legacy: ['SV-57607', 'V-44773']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

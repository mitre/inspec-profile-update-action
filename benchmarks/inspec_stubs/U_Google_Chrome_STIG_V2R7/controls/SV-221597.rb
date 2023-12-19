control 'SV-221597' do
  title 'Anonymized data collection must be disabled.'
  desc 'Enable URL-keyed anonymized data collection in Google Chrome and prevent users from changing this setting.
URL-keyed anonymized data collection sends URLs of pages the user visits to Google to make searches and browsing better.
If you enable this policy, URL-keyed anonymized data collection is always active.
If you disable this policy, URL-keyed anonymized data collection is never active.
If this policy is left not set, URL-keyed anonymized data collection will be enabled but the user will be able to change it.'
  desc 'check', 'Universal method: 
1. In the omnibox (address bar) type chrome://policy
2. If "UrlKeyedAnonymizedDataCollectionEnabled" is not displayed under the “Policy Name” column or it is not set to "0" under the “Policy Value” column, this is a finding.
Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the “UrlKeyedAnonymizedDataCollectionEnabled" value name does not exist or its value data is not set to "0," this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with gpedit.msc
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
Policy Name: Enable URL-keyed anonymized data collection
Policy State: Disabled
Policy Value: NA'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23312r415918_chk'
  tag severity: 'medium'
  tag gid: 'V-221597'
  tag rid: 'SV-221597r615937_rule'
  tag stig_id: 'DTBC-0066'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-23301r415919_fix'
  tag 'documentable'
  tag legacy: ['SV-101303', 'V-91203']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end

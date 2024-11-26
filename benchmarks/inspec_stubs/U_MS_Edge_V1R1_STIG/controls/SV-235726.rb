control 'SV-235726' do
  title 'The default search provider must be set to use an encrypted connection.'
  desc 'Allows a list of list of up to 10 search engines to be configured, one of which must be marked as the default search engine. The encoding does not need to be specified. Starting in Microsoft Edge 80, the suggest_url and image_search_url parameters are optional. The optional parameter, image_search_post_params (consists of comma-separated name/value pairs), is available starting in Microsoft Edge 80.

Starting in Microsoft Edge 83, search engine discovery can be enabled with the allow_search_engine_discovery optional parameter. This parameter must be the first item in the list. If allow_search_engine_discovery is not specified, search engine discovery will be disabled by default. Starting in Microsoft Edge 84, this policy can be set as a recommended policy to allow search provider discovery. The allow_search_engine_discovery optional parameter does not need to be added.

If this policy is enabled, users cannot add, remove, or change any search engine in the list. Users can set their default search engine to any search engine in the list.

If this policy is disabled or not configured, users can modify the search engines list as desired.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Manage Search Engines" must be configured.

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\Recommended

Example REG_SZ value text:
[{"allow_search_engine_discovery": false},{"is_default": true,"name": "Microsoft Bing","keyword": "bing","search_url": "https://www.bing.com/search?q={searchTerms}"},{"name": "Google","keyword": "google","search_url": "https://www.google.com/search?q={searchTerms}"}]

If any of the search URLs in the list do not begin with "https", this is a finding.'
  desc 'fix', 'Configure the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Manage Search Engines".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38945r626374_chk'
  tag severity: 'medium'
  tag gid: 'V-235726'
  tag rid: 'SV-235726r626523_rule'
  tag stig_id: 'EDGE-00-000009'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38908r626375_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

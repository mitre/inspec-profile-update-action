control 'SV-221565' do
  title 'The default search provider URL must be set to perform encrypted searches.'
  desc "Specifies the URL of the search engine used when doing a default search. The URL should contain the string '{searchTerms}', which will be replaced at query time by the terms the user is searching for. This option must be set when the 'DefaultSearchProviderEnabled' policy is enabled and will only be respected if this is the case.  When doing internet searches it is important to use an encrypted connection via https."
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

Universal method: 
 1. In the omnibox (address bar) type chrome://policy 
 2. If DefaultSearchProviderSearchURL is not displayed under the Policy Name column or it is not set to an organization-approved encrypted search string (ex. https://www.google.com/?q={searchTerms} or https://www.bing.com/search?q={searchTerms} ) under the Policy Value column, this is a finding.

Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the DefaultSearchProviderSearchURL value name does not exist or its value data is not set to an organization-approved encrypted search string (ex. https://www.google.com/search?q={searchTerms} or https://www.bing.com/search?q={searchTerms} ) this is a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Windows group policy:
 1. Open the group policy editor tool with gpedit.msc 
 2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Default search provider\\
 Policy Name: Default search provider search URL
 Policy State: Enabled
 Policy Value: Must be set to an organization-approved encrypted search string 
 (ex. https://www.google.com/search?q={searchTerms} or https://www.bing.com/search?q={searchTerms} )'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23280r684819_chk'
  tag severity: 'medium'
  tag gid: 'V-221565'
  tag rid: 'SV-221565r684821_rule'
  tag stig_id: 'DTBC-0008'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23269r684820_fix'
  tag 'documentable'
  tag legacy: ['SV-57569', 'V-44735']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

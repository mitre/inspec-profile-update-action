control 'SV-234114' do
  title 'The Tanium documentation identifying recognized and trusted folders for Detect Local Directory Source must be maintained.'
  desc 'An IOC stream is a series or "stream" of IOCs that are imported from a vendor based on a subscription service or manually downloaded and placed in a folder. Detect can be configured to retrieve the IOC content on a regularly scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of folder maintainers for Detect Local Directory Source.

If the site does not leverage Local Directory Source to import IOCs, this finding is Not Applicable.

If the site does use Local Directory Source to import IOCs and the folder maintainers are not documented, this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium IOC Local Directory Source maintainers.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37299r610842_chk'
  tag severity: 'medium'
  tag gid: 'V-234114'
  tag rid: 'SV-234114r612749_rule'
  tag stig_id: 'TANS-SV-000048'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-37264r610843_fix'
  tag 'documentable'
  tag legacy: ['SV-102301', 'V-92199']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

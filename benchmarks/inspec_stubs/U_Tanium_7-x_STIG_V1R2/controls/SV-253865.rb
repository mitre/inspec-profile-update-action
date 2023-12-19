control 'SV-253865' do
  title 'The Tanium documentation identifying recognized and trusted folders for Threat Response Local Directory Source must be maintained.'
  desc 'Using trusted and recognized indicator of compromise (IOC) sources may detect and prevent systems from becoming compromised. An IOC stream is a series or stream of IOCs that are imported from a vendor based on a subscription service or manually downloaded and placed in a folder. Threat Response can be configured to retrieve the IOC content on a regularly scheduled basis. The items in an IOC stream can be manipulated separately after they are imported.'
  desc 'check', 'Consult with the Tanium system administrator to review the documented list of folder maintainers for Threat Response Local Directory Source.

If the site does not leverage Local Directory Source to import IOCs, this finding is not applicable.

If the site does use Local Directory Source to import IOCs and the folder maintainers are not documented, this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium Threat Response Local Directory Source maintainers.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57317r842621_chk'
  tag severity: 'medium'
  tag gid: 'V-253865'
  tag rid: 'SV-253865r842623_rule'
  tag stig_id: 'TANS-SV-000048'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-57268r842622_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

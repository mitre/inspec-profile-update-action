control 'SV-253842' do
  title 'The Tanium documentation identifying recognized and trusted indicator of compromise (IOC) streams must be maintained.'
  desc 'Using trusted and recognized IOC sources may detect compromise and prevent systems from becoming compromised. An IOC stream is a series or stream of IOCs that are imported from a vendor based on a subscription service. An IOC stream can be downloaded manually or on a scheduled basis. The items in an IOC stream can be manipulated separately after they are imported.'
  desc 'check', 'Consult with the Tanium system administrator to determine if the Threat Response module is being used. If it is not, this is not applicable.

Review the documented list of IOC trusted stream sources.

If the site uses an external source for IOCs and the IOC trusted stream source is not documented, this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Threat Response trusted stream sources.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57294r842552_chk'
  tag severity: 'medium'
  tag gid: 'V-253842'
  tag rid: 'SV-253842r842554_rule'
  tag stig_id: 'TANS-SV-000007'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-57245r842553_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

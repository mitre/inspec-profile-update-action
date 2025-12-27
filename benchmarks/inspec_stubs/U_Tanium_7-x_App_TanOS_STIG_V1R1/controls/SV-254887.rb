control 'SV-254887' do
  title 'The Tanium documentation identifying recognized and trusted IOC streams must be maintained.'
  desc 'Using trusted and recognized IOC sources may detect and prevent systems from becoming compromised. An IOC stream is a series or stream of IOCs that are imported from a vendor based on a subscription service. An IOC stream can be downloaded manually or on a scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Consult with the Tanium System Administrator to determine if the Threat Response module is being used. If not, this is Not Applicable.

Review the documented list of IOC trusted stream sources.

If the site does use an external source for IOCs and the IOC trusted stream source is not documented, this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Threat Response trusted stream sources.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58500r867559_chk'
  tag severity: 'medium'
  tag gid: 'V-254887'
  tag rid: 'SV-254887r867561_rule'
  tag stig_id: 'TANS-AP-000130'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-58444r867560_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

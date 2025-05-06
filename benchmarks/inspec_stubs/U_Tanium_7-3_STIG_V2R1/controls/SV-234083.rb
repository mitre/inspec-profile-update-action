control 'SV-234083' do
  title 'The Tanium documentation identifying recognized and trusted Intel streams must be maintained.'
  desc 'An IOC stream is a series or stream of IOCs that are imported from a vendor based on a subscription service. An IOC stream can be downloaded manually or on a scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Consult with the Tanium System Administrator to determine if the "Tanium Detect" module is being used, if not this is Not Applicable.

Review the documented list of IOC trusted stream sources.

If the site does use an external source for IOCs and the IOC trusted stream source is not documented, this is a finding.'
  desc 'fix', 'Consult with the Tanium System Administrator to determine if the "Tanium Detect" module is being used, if not this is Not Applicable.

Prepare and maintain documentation identifying the Tanium Detect IOC trusted stream sources.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37268r610749_chk'
  tag severity: 'medium'
  tag gid: 'V-234083'
  tag rid: 'SV-234083r612749_rule'
  tag stig_id: 'TANS-SV-000007'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-37233r610750_fix'
  tag 'documentable'
  tag legacy: ['SV-102239', 'V-92137']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

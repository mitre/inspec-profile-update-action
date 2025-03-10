control 'SV-81537' do
  title 'The Tanium documentation identifying recognized and trusted IOC Detect streams must be maintained.'
  desc 'An IOC stream is a series or “stream” of IOCs that are imported from a vendor based on a subscription service. An IOC stream can be downloaded manually or on a scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of IOC trusted stream sources.

If the site does not have IOC trusted stream sources documented, this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium IOC trusted stream sources.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67683r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67047'
  tag rid: 'SV-81537r1_rule'
  tag stig_id: 'TANS-SV-000007'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-73147r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

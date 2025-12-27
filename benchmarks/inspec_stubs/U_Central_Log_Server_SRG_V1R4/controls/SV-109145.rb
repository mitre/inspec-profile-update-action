control 'SV-109145' do
  title 'The Central Log Server must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server generates audit records when successful/unsuccessful logon attempts occur.

If the Central Log Server is not configured to generate audit records when successful/unsuccessful logon attempts occur, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to generate audit records when successful/unsuccessful logon attempts occur.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-100041'
  tag rid: 'SV-109145r1_rule'
  tag stig_id: 'SRG-APP-000503-AU-000280'
  tag gtitle: 'SRG-APP-000503-AU-000280'
  tag fix_id: 'F-105725r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

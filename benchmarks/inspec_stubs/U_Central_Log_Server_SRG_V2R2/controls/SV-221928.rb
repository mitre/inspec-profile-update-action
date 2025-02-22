control 'SV-221928' do
  title 'The Central Log Server must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server generates audit records when successful/unsuccessful logon attempts occur.

If the Central Log Server is not configured to generate audit records when successful/unsuccessful logon attempts occur, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to generate audit records when successful/unsuccessful logon attempts occur.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23643r420126_chk'
  tag severity: 'medium'
  tag gid: 'V-221928'
  tag rid: 'SV-221928r420128_rule'
  tag stig_id: 'SRG-APP-000503-AU-000280'
  tag gtitle: 'SRG-APP-000503'
  tag fix_id: 'F-23632r420127_fix'
  tag 'documentable'
  tag legacy: ['SV-109145', 'V-100041']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

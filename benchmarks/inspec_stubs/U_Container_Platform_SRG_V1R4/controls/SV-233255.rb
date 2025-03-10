control 'SV-233255' do
  title 'The container platform must generate audit records when successful/unsuccessful attempts to modify privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the container platform configuration to verify audit records are generated on successful/unsuccessful attempts to modify privileges. 

If audit records are not generated, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records on successful/unsuccessful attempts to modify privileges.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36191r601252_chk'
  tag severity: 'medium'
  tag gid: 'V-233255'
  tag rid: 'SV-233255r879866_rule'
  tag stig_id: 'SRG-APP-000495-CTR-001235'
  tag gtitle: 'SRG-APP-000495'
  tag fix_id: 'F-36159r601253_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

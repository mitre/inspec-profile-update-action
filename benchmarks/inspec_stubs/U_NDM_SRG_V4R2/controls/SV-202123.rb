control 'SV-202123' do
  title 'The network device must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records when successful/unsuccessful logon attempts occur.

If it does not generate audit records when successful/unsuccessful logon attempts occur, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records when successful/unsuccessful logon attempts occur.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2249r382049_chk'
  tag severity: 'medium'
  tag gid: 'V-202123'
  tag rid: 'SV-202123r879874_rule'
  tag stig_id: 'SRG-APP-000503-NDM-000320'
  tag gtitle: 'SRG-APP-000503'
  tag fix_id: 'F-2250r382050_fix'
  tag 'documentable'
  tag legacy: ['SV-69523', 'V-55277']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

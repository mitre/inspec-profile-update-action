control 'SV-202122' do
  title 'The network device must generate audit records when successful/unsuccessful attempts to delete administrator privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records when successful/unsuccessful attempts to delete administrator privileges occur.

If the network device does not generate audit records when successful/unsuccessful attempts to delete administrator privileges occur, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records when successful/unsuccessful attempts to delete administrator privileges occur.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2248r382046_chk'
  tag severity: 'medium'
  tag gid: 'V-202122'
  tag rid: 'SV-202122r879870_rule'
  tag stig_id: 'SRG-APP-000499-NDM-000319'
  tag gtitle: 'SRG-APP-000499'
  tag fix_id: 'F-2249r382047_fix'
  tag 'documentable'
  tag legacy: ['SV-69521', 'V-55275']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
